-- | An occasionally pure, monadic interface to AES
module Codec.Crypto.AES.Monad(
  AES, Mode(..), Direction(..), Cryptable(..), runAEST, runAES
  ) where

import qualified Codec.Crypto.AES.IO as AES
import Codec.Crypto.AES.IO(Mode(..), Direction(..), newCtx, AESCtx)
import Control.Applicative
import Control.Monad.ST.Lazy
import Control.Monad.Reader
import Control.Monad.Writer
import Control.Monad.UnsafeIO
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL

type AEST m a = ReaderT AESCtx (WriterT BL.ByteString m) a

type AES s a = AEST (ST s) a

-- | Run an AES computation
runAEST :: MonadUnsafeIO m =>
          Mode
          -> B.ByteString -- ^ The AES key - 16, 24 or 32 bytes
          -> B.ByteString -- ^ The IV, 16 bytes
          -> Direction
          -> AEST m a
          -> m (a, BL.ByteString)
runAEST mode key iv dir aes = do
  ctx <- liftUnsafeIO $ newCtx mode key iv dir
  runWriterT $ runReaderT aes ctx

-- | Run an AES computation
runAES ::  Mode
          -> B.ByteString -- ^ The AES key - 16, 24 or 32 bytes
          -> B.ByteString -- ^ The IV, 16 bytes
          -> Direction
          -> (forall s. AES s a)
          -> (a, BL.ByteString)
runAES mode key iv dir aes = runST $ runAEST mode key iv dir aes

-- | A class of things that can be crypted
--
-- The crypt function returns incremental results as well as
-- appending them to the result bytestring.
class Cryptable a where
  crypt :: a -> AES s a

instance Cryptable B.ByteString where
  crypt bs = do
    ctx <- ask
    crypted <- liftUnsafeIO $ AES.crypt ctx bs
    tell $ BL.fromChunks [crypted]
    return crypted

instance Cryptable BL.ByteString where
  crypt (BL.toChunks -> chunks) = snd <$> listen (mapM_ crypt chunks)
