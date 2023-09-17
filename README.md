_This repository has been moved to:_

https://gitlab.com/daniel-casanueva/haskell/gmail-simple

# gmail-simple

A library for [Haskell](https://www.haskell.org) that provides functions to easily
interact with the [Google Mail API](https://developers.google.com/gmail/api).
It doesn't intend to be fully featured, but rather simple.

## Current features

* OAuth management.
* Mail sending.
* Plain text and HTML supported.

Feel free to open an issue if you are interested in the addition of
some specific feature.

## Required scopes

In order to use the Google API, you need to enable scopes on your account.
Here are the ones you'll need for this library, depending on what you want to do.

* For sending mails: `https://www.googleapis.com/auth/gmail.send`.

## GHC Compatibility

Stack is used to check for compatibility against different GHC versions and dependencies.
To see the list of supported snapshots, see [build-script.sh](https://github.com/Daniel-Diaz/gmail-simple/blob/main/build-script.sh).
