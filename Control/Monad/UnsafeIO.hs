-- | Just like MonadIO, but codifying /unsafe/ IO execution. Exists for safety.
module Control.Monad.UnsafeIO where

import qualified Control.Monad.ST as S
import qualified Control.Monad.ST.Lazy as L
import Control.Monad.Trans.Reader
import Control.Monad.Trans.Writer
import Control.Monad.Trans
import Data.Monoid

class Monad m => MonadUnsafeIO m where
  liftUnsafeIO :: IO a -> m a

instance MonadUnsafeIO IO where
  liftUnsafeIO = id
instance MonadUnsafeIO (S.ST s) where
  liftUnsafeIO = S.unsafeIOToST
instance MonadUnsafeIO (L.ST s) where
  liftUnsafeIO = L.unsafeIOToST
instance MonadUnsafeIO m => MonadUnsafeIO (ReaderT r m) where
  liftUnsafeIO = lift . liftUnsafeIO
instance (Monoid w, MonadUnsafeIO m) => MonadUnsafeIO (WriterT w m) where
  liftUnsafeIO = lift . liftUnsafeIO
