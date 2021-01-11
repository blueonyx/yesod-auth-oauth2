{-# LANGUAGE OverloadedStrings #-}
-- |
--
-- OAuth2 plugin for https://steadyhq.com
--
-- * Authenticates against upcase
-- * Uses user id as credentials identifier
-- * Note: steady doesn't accept 'localhost' as domain in the callback URL,
--   use 127.0.0.1 instead and don't forget to set your 'approot' accordingly
--
module Yesod.Auth.OAuth2.Steady
    ( oauth2Steady ) where

import Yesod.Auth.OAuth2.Prelude

import Control.Applicative ((<|>))
import Data.Aeson (withText)

newtype User = User Text

instance FromJSON User where
    parseJSON x = pO <|> pS
      where
        pO = withObject "User" (\o -> o .: "data") x >>= withObject "User.Data" (\p -> p .: "id")
        pS = withText "User" (\t -> return $ User t) x


pluginName :: Text
pluginName = "steady"

defaultScopes :: [Text]
defaultScopes = ["read"]

oauth2Steady :: YesodAuth m => Text -> Text -> AuthPlugin m
oauth2Steady = oauth2SteadyScoped defaultScopes

-- not exported, because only one valid scope available
oauth2SteadyScoped :: YesodAuth m => [Text] -> Text -> Text -> AuthPlugin m
oauth2SteadyScoped scopes clientId clientSecret =
    authOAuth2 pluginName oauth2 $ \manager token -> do
        (User userId, userResponse) <- authGetProfile
            pluginName
            manager
            token
            "https://steadyhq.com/api/v1/users/me"

        pure Creds
            { credsPlugin = pluginName
            , credsIdent  = userId
            , credsExtra  = setExtra token userResponse
            }
  where
    oauth2 = OAuth2
        { oauthClientId            = clientId
        , oauthClientSecret        = Just clientSecret
        , oauthOAuthorizeEndpoint  =
            "https://steadyhq.com/oauth/authorize"
              `withQuery` [scopeParam " " scopes]
        , oauthAccessTokenEndpoint =
            "https://steadyhq.com/api/v1/oauth/token"
              `withQuery` [("client_id",encodeUtf8 clientId)]
        , oauthCallback            = Nothing
        }
