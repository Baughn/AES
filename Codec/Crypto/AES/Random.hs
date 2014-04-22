-- | This module provides a cryptographically secure PRNG based on
-- AES, reading the seed from /dev/random
module Codec.Crypto.AES.Random(randBytes,prandBytes,AESGen,newAESGen) where

import Data.Serialize
import System.IO.Unsafe
import System.IO
import System.Random
import Control.Applicative
import Prelude hiding(head)
import Codec.Crypto.AES.IO
import Control.Concurrent.MVar
import qualified Data.ByteString as B
import Data.List

-- | Randomness from a system source of nonsense such as /dev/random
randBytes :: Int -> IO B.ByteString
randBytes n = withFile "/dev/random" ReadMode $ \h -> B.hGet h n

{-# NOINLINE ctx #-}
ctx :: MVar AESCtx
ctx = unsafePerformIO $ do
  key <- randBytes 16
  iv <- randBytes 16
  newMVar =<< newCtx CTR key iv Encrypt
  
-- | Cryptographic pseudorandomness from an AES cipher. This function
-- is currently inefficient for non-multiple-of-16 sized bytestrings.
prandBytes :: Int -> IO B.ByteString
prandBytes n = withMVar ctx $ \aesctx -> do
  bytes <- crypt aesctx $ B.replicate (((n+15) `div` 16) * 16) 0
  return $ B.take n bytes

-- | A random number generator that gets its input from prandBytes,
-- ensuring purity by storing those bytes for later if you don't
-- discard the generator.
--
-- Using split on this generator isn't supported, but could be.
--
-- Please note that if an asynchronous exception is caught while a
-- random number is being generated, the generator will be wrecked
-- forevermore.
newtype AESGen = RND [Int]

instance Show AESGen where
  show _ = "AESGen [...]"

instance RandomGen AESGen where
  next (RND (i:is)) = (i,RND is)
  next (RND []) = undefined
  split _ = error "split not supported on Codec.Crypto.AES.Random.AESGen"

intSizeInBinary :: Int
intSizeInBinary = fromIntegral $ B.length $ encode (0::Int)

newAESGen :: IO AESGen
newAESGen = RND <$> gen
  where gen = unsafeInterleaveIO $ do
          bytes <- prandBytes 64
          let chunks = unfoldr (\b -> if B.null b then Nothing else Just (B.splitAt intSizeInBinary b)) bytes
              ints = map ((\(Right i) -> i) . decode) chunks
          moreInts <- gen
          return (ints ++ moreInts)
