-- | A pure interface to AES
module Codec.Crypto.AES(
  Mode(..), Direction(..), crypt, crypt'
  ) where

import qualified Codec.Crypto.AES.ST as AES
import Codec.Crypto.AES.ST(Mode(..), Direction(..))
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL

-- | Encryption/decryption for lazy bytestrings
crypt :: Mode
        -> B.ByteString -- ^ The AES key - 16, 24 or 32 bytes
        -> B.ByteString -- ^ The IV, 16 bytes
        -> Direction 
        -> BL.ByteString -- ^ Bytestring to encrypt/decrypt
        -> BL.ByteString
crypt mode key iv dir bs = AES.execAES mode key iv dir (AES.crypt bs)

-- | Encryption/decryption for strict bytestrings
crypt' :: Mode
         -> B.ByteString -- ^ The AES key - 16, 24 or 32 bytes
         -> B.ByteString -- ^ The IV, 16 bytes
         -> Direction 
         -> B.ByteString -- ^ Bytestring to encrypt/decrypt
         -> B.ByteString
crypt' mode key iv dir bs = B.concat $ BL.toChunks $ AES.execAES mode key iv dir (AES.crypt bs)
