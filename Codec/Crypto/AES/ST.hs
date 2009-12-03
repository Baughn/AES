-- | A pure interface to AES, in the lazy ST monad.
module Codec.Crypto.AES.ST(
  AES, Mode(..), Direction(..), Cryptable(..), execAES, runAES, liftST
  ) where

import qualified Codec.Crypto.AES.IO as AES
import Codec.Crypto.AES.IO(Mode(..), Direction(..), newCtx, AESCtx)
import Control.Applicative
import Control.Monad.ST.Lazy
import Control.Monad.Reader
import Control.Monad.Writer
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL

type AES s a = ReaderT AESCtx (WriterT BL.ByteString (ST s)) a

-- | Before you use this, recall that AES uses the lazy ST monad.
liftST :: ST s a -> AES s a
liftST = lift . lift

-- | Compute an AES computation, returning the ST return value along
-- with the crypted data
runAES :: Mode
         -> B.ByteString -- ^ The AES key - 16, 24 or 32 bytes
         -> B.ByteString -- ^ The IV, 16 bytes
         -> Direction
         -> (forall s. AES s a)
         -> (a, BL.ByteString)
runAES mode key iv dir aes = runST $ do
  ctx <- unsafeIOToST $ newCtx mode key iv dir
  runWriterT $ runReaderT aes ctx

-- | Compute an AES computation, discarding the ST return value
execAES :: Mode
          -> B.ByteString -- ^ The AES key - 16, 24 or 32 bytes
          -> B.ByteString -- ^ The IV, 16 bytes
          -> Direction
          -> (forall s. AES s a)
          -> BL.ByteString
execAES mode key iv dir aes = snd $ runAES mode key iv dir aes

-- | A class of things that can be crypted
--
-- The crypt function returns incremental results as well as
-- appending them to the result bytestring.
class Cryptable a where
  crypt :: a -> AES s a

instance Cryptable B.ByteString where
  crypt bs = do
    ctx <- ask
    crypted <- liftST $ unsafeIOToST $ AES.crypt ctx bs
    tell $ BL.fromChunks [crypted]
    return crypted

instance Cryptable BL.ByteString where
  crypt (BL.toChunks -> chunks) = snd <$> listen (mapM_ crypt chunks)
