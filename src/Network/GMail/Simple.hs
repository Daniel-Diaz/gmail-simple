
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE FlexibleInstances #-}

-- | Interactions with GMail made simple.
--
--   == Sending mails
--
--   For now, only mail sending is implemented.
--   Here's an example:
--
--   First we read the Google key file.
--
-- > do gkey <- readKeyFile "google-key.json"
--
--   Then we start a session. We provide the
--   mail address of the user that will send
--   the mail.
--
-- >    session <- newSession gkey "sender@example.com"
--
--   Here's the mail description.
--
-- >    let mail :: Mail Text
-- >        mail = Mail
-- >          { mail_sender = "Me"
-- >          , mail_recipient = "recipient@example.com"
-- >          , mail_subject = "Example mail"
-- >          , mail_body = "This is an example mail."
-- >            }
--
--   Finally, we simply send the mail.
--
-- >    sendMail session mail
--
--   That's it.
--
--   == Importing this library
--
--   I would recommend importing this module qualified. For example:
--
-- > import qualified Network.GMail.Simple as GMail
--
--
module Network.GMail.Simple
  ( -- * Key
    Key (..)
  , readKeyFile
    -- * Session
  , Session
  , newSession
    -- * Mail
  , MailAddress (..)
  , Mail (..)
  , sendMail
    -- * Mail body
  , ToMailBody (..)
    -- * Exceptions
  , GMailException (..)
    ) where

-- TODO: Better organize the import list
import Control.Monad (unless)
import Control.Exception (Exception, throwIO)
import Control.Concurrent (MVar, newMVar, modifyMVar)
import Data.Proxy (Proxy (..))
import Data.String (IsString (..))
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.Lazy as LazyText
import Data.Text.Encoding (encodeUtf8, decodeUtf8)
import qualified Web.JWT as JWT
import qualified Data.HashMap.Strict as HashMap
import qualified Data.Aeson as JSON
import qualified Network.HTTP.Simple as HTTP
import Data.ByteString.Base64 (encodeBase64)
import Network.HTTP.Media (MediaType)
import qualified Network.HTTP.Media as Media
import Data.Time.Clock (NominalDiffTime)
import Data.Time.Clock.POSIX (POSIXTime, getPOSIXTime)
import qualified Web.FormUrlEncoded as URLEncoded
import Crypto.PubKey.RSA.Types (PrivateKey)
import qualified Data.Map as Map
import Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as LazyB
import Text.Blaze.Html (Html)
import qualified Text.Blaze.Html.Renderer.Text as HTML

-- | A mail address as text.
newtype MailAddress = MailAddress Text

mailAddressText :: MailAddress -> Text
mailAddressText (MailAddress t) = t

instance IsString MailAddress where
  fromString = MailAddress . fromString

-- | Mail datatype.
data Mail a = Mail
  { -- | Sender's alias.
    mail_sender :: Text
    -- | The recipient of this mail.
  , mail_recipient :: MailAddress
    -- | The subject of this mail.
  , mail_subject :: Text
    -- | Polymorphic mail body.
  , mail_body :: a
    }

-- | You can use `fmap` to map a function over the body of a mail.
instance Functor Mail where
  fmap f mail = mail { mail_body = f $ mail_body mail }

-- | Google API Key from a service account. You can create one
--   inside your project in <https://console.cloud.google.com Google Cloud>.
--   Once you have it, you can download it to a file and read it using 'readKeyFile'.
data Key = Key
  { private_key    :: PrivateKey
  , private_key_id :: Text
  , client_email   :: MailAddress
    }

-- | Read the key file provided by Google Cloud.
--   It throws a 'FailedToParseKey' exception when
--   the file fails to parse.
--
--   If you don't want to read it from a local file,
--   you can use the `JSON.FromJSON` instance of `Key`
--   to read it. The function 'readKeyFile' is just a
--   wrapper around that.
readKeyFile :: FilePath -> IO Key
readKeyFile fp = LazyB.readFile fp >>=
  either (throwIO . FailedToParseKey) pure . JSON.eitherDecode

instance JSON.FromJSON Key where
  parseJSON = JSON.withObject "Key" $ \o -> do
    pkt <- o JSON..: "private_key"
    case JWT.readRsaSecret $ encodeUtf8 pkt of
      Just pk -> Key
        <$> pure pk
        <*> o JSON..: "private_key_id"
        <*> (MailAddress <$> o JSON..: "client_email")
      _ -> fail "Error parsing private key."

data OAuth = OAuth
  { oauth_access_token :: Text
  , oauth_expires_in :: NominalDiffTime
    }

instance JSON.FromJSON OAuth where
  parseJSON = JSON.withObject "OAuth" $ \o ->
    OAuth <$> o JSON..: "access_token" <*> o JSON..: "expires_in"

oauthQuery
  :: Key -- ^ Google key
  -> MailAddress -- ^ Sender mail address
  -> IO OAuth
oauthQuery k sender = do
  now <- getPOSIXTime
  let -- JWT Header
      h = JWT.JOSEHeader
            { JWT.typ = Just "JWT"
            , JWT.cty = Nothing
            , JWT.alg = Just JWT.RS256
            , JWT.kid = Nothing
              }
      -- Scoped required to send mails
      scope :: Text
      scope = "https://www.googleapis.com/auth/gmail.send"
      -- JWT Claims
      c = JWT.JWTClaimsSet
            { JWT.iss = JWT.stringOrURI $ mailAddressText $ client_email k
            , JWT.sub = JWT.stringOrURI $ mailAddressText sender
            , JWT.aud = Left <$> JWT.stringOrURI "https://oauth2.googleapis.com/token"
            , JWT.unregisteredClaims = JWT.ClaimsMap $ Map.singleton "scope" $ JSON.toJSON scope
            , JWT.iat = JWT.numericDate now
            , JWT.exp = JWT.numericDate $ now + 3600
            , JWT.nbf = Nothing
            , JWT.jti = Nothing
              }
      -- Signed JWT
      jwt = JWT.encodeSigned (JWT.RSAPrivateKey $ private_key k) h c
      -- HTTP request body
      body :: ByteString
      body = URLEncoded.urlEncodeForm $ URLEncoded.Form $ HashMap.fromList
               [ ("grant_type", ["urn:ietf:params:oauth:grant-type:jwt-bearer"])
               , ("assertion", [jwt])
                 ]
      -- HTTP request
      req :: HTTP.Request
      req = HTTP.setRequestMethod "POST"
          $ HTTP.setRequestSecure True
          $ HTTP.setRequestPort 443
          $ HTTP.setRequestHost "oauth2.googleapis.com"
          $ HTTP.setRequestPath "/token"
          $ HTTP.addRequestHeader "Content-Type" "application/x-www-form-urlencoded"
          $ HTTP.setRequestBodyLBS body
          $ HTTP.defaultRequest
  HTTP.getResponseBody <$> HTTP.httpJSON req 

data OAuthWithTimestamp = OAuthWithTimestamp
  { oauth_value :: OAuth
  , oauth_time :: POSIXTime
    }

-- | A session that can be used to send mails.
--
--   * It may be reused.
--   * Multiple threads can use it simultaneously.
data Session = Session
  { session_key :: Key
  , session_sender :: MailAddress
  , session_oauth :: MVar OAuthWithTimestamp
    }

-- | Create a new session for the given sender.
newSession
  :: Key -- ^ Google API key
  -> MailAddress -- ^ Mail address of the sender
  -> IO Session
newSession k sender = do
  oauth <- oauthQuery k sender
  now <- getPOSIXTime
  let oauthw = OAuthWithTimestamp
        { oauth_value = oauth
        , oauth_time = now
          }
  Session k sender <$> newMVar oauthw

withOAuth :: Session -> (OAuth -> IO a) -> IO a
withOAuth session f = modifyMVar (session_oauth session) $ \oauthw -> do
  let oauth = oauth_value oauthw
  now <- getPOSIXTime
  -- We renew the token 5 seconds earlier
  if now + 5 < oauth_time oauthw + oauth_expires_in oauth
     then (,) oauthw <$> f oauth
     else do oauth' <- oauthQuery (session_key session) (session_sender session)
             now' <- getPOSIXTime
             let oauthw' = OAuthWithTimestamp
                   { oauth_value = oauth'
                   , oauth_time = now'
                     }
             (,) oauthw' <$> f oauth'

renderMail :: forall a . ToMailBody a => MailAddress -> Mail a -> JSON.Value
renderMail sender mail = JSON.Object $ HashMap.singleton "raw" $ JSON.String
    $ Text.replace "+" "-"
    $ Text.replace "/" "_"
    $ encodeBase64
    $ encodeUtf8 $ Text.concat
        [ "From: " <> mail_sender mail <> " <" <> mailAddressText sender <> ">\r\n"
        , "To: " <> mailAddressText (mail_recipient mail) <> "\r\n"
        , "Subject: " <> mail_subject mail <> "\r\n"
        , "Content-Type: " <> decodeUtf8 (Media.renderHeader $ mailContentType (Proxy :: Proxy a)) <> "\r\n"
        , "\r\n"
        , toMailBody $ mail_body mail
          ]

-- | Exceptions thrown by functions in this library.
data GMailException =
    -- | A mail failed to be sent. The JSON value contains
    --   the error message as sent by Google.
    FailedToSend JSON.Value
    -- | A key file failed to parse. The string contains
    --   the parsing error.
  | FailedToParseKey String
    deriving Show

instance Exception GMailException

-- | Send mail using a session. It might throw a 'FailedToSend' exception.
--
--   In order for this to work, the user must have permissions for the @https://www.googleapis.com/auth/gmail.send@ scope.
sendMail :: ToMailBody a => Session -> Mail a -> IO ()
sendMail session mail = withOAuth session $ \oauth -> do
  let mailReq :: HTTP.Request
      mailReq = HTTP.setRequestMethod "POST"
              $ HTTP.setRequestSecure True
              $ HTTP.setRequestPort 443
              $ HTTP.setRequestHost "gmail.googleapis.com"
              $ HTTP.setRequestPath ("/gmail/v1/users/me/messages/send")
              $ HTTP.setRequestQueryString [("key",Just $ encodeUtf8 $ private_key_id $ session_key session)]
              $ HTTP.addRequestHeader "Authorization" ("Bearer " <> encodeUtf8 (oauth_access_token oauth))
              $ HTTP.setRequestBodyJSON (renderMail (session_sender session) mail)
              $ HTTP.defaultRequest
  resp <- HTTP.httpJSON mailReq
  let respCode = HTTP.getResponseStatusCode resp
  unless (div respCode 100 == 2) $ throwIO $ FailedToSend $ HTTP.getResponseBody resp

-- ToMailBody class and instances

-- | Class of types that can be used as mail body.
class ToMailBody a where
  -- | Textual representation of the mail body.
  toMailBody :: a -> Text
  -- | Value for the @Content-Type@ header.
  mailContentType :: proxy a -> MediaType

instance ToMailBody Text where
  toMailBody = id
  mailContentType _ = "text" Media.// "plain"

instance ToMailBody Html where
  toMailBody = LazyText.toStrict . HTML.renderHtml
  mailContentType _ = "text" Media.// "html"
