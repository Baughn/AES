-- | Primitive (in IO) AES operations
{-# CFILES cbits/aescrypt.c cbits/aeskey.c cbits/aestab.c cbits/aes_modes.c #-}
module Codec.Crypto.AES.IO(
  newCtx, newECBCtx, Direction(..), Mode(..), AESCtx, crypt
  ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as BI

import Foreign
import Control.Applicative
import Control.Monad
import Data.IORef

#include "aesopt.h"
#include "aes.h"
#include "aestab.h"
#include "brg_endian.h"
#include "ctr_inc.h"

newtype AESKey = AESKey B.ByteString
               deriving(Show)


toKey :: B.ByteString -- ^ Must be 16, 24 or 32 bytes
        -> AESKey
toKey bs | B.length bs `elem` [16,24,32] = AESKey bs
         | otherwise = error $ "toKey: Key has wrong length: " ++ show (B.length bs)

newtype IV = IV (ForeignPtr Word8)

{-# NOINLINE toIV #-}
toIV :: B.ByteString -> IV
toIV bs | B.length bs == 16 = let (bsPtr,0,16) = BI.toForeignPtr (B.copy bs) in IV bsPtr
        | otherwise = error $ "toIV: IV has wrong length: " ++ show (B.length bs)

data Direction = Encrypt | Decrypt

-- | Modes ECB and CBC can only handle full 16-byte frames. This means
-- the length of every strict bytestring passed in must be a multiple
-- of 16; when using lazy bytestrings, its /component/ strict
-- bytestrings must all satisfy this.
--
-- Other modes can handle bytestrings of any length, by storing
-- overflow for later. However, the total length of bytestrings passed
-- in must still be a multiple of 16, or the overflow will be lost.
--
-- For OFB and CTR, Encrypt and Decrypt are the same operation. For
-- CTR, the IV is the initial value of the counter.
data Mode = ECB | CBC | CFB  | OFB  | CTR

data Context = ECBCtx DirectionalCtx
             | CBCCtx IV DirectionalCtx
             | CFBCtx IV Direction EncryptCtxP
             | OFBCtx IV EncryptCtxP
             | CTRCtx IV EncryptCtxP



data AESCtx = AESCtx Context (IORef Int)

data DirectionalCtx = EncryptCtx EncryptCtxP
                    | DecryptCtx DecryptCtxP

-- | Create an encryption/decryption context for incremental
-- encryption/decryption
--
-- You may create an ECB context this way, in which case you may pass
-- undefined for the IV
newCtx :: Mode
         -> B.ByteString -- ^ A 16, 24 or 32-byte AES key
         -> B.ByteString -- ^ A 16-byte IV
         -> Direction 
         -> IO AESCtx
newCtx mode (toKey -> key) (toIV -> iv) dir = wrapCtr =<< newCtx' key iv mode dir

newCtx' :: AESKey -> IV -> Mode -> Direction -> IO Context
newCtx' key _ ECB dir      = newECBCtx' key dir
newCtx' key iv CBC Encrypt = CBCCtx iv . EncryptCtx <$> encryptCtx key
newCtx' key iv CBC Decrypt = CBCCtx iv . DecryptCtx <$> decryptCtx key
newCtx' key iv CFB dir     = CFBCtx iv dir <$> encryptCtx key
newCtx' key iv OFB _       = OFBCtx iv <$> encryptCtx key
newCtx' key iv CTR _       = CTRCtx iv <$> encryptCtx key

wrapCtr :: Context -> IO AESCtx
wrapCtr ctx = AESCtx ctx <$> newIORef 0

-- | Create a context for ECB, which doesn't need an IV
newECBCtx :: B.ByteString -- ^ A 16, 24 or 32-byte AES key
            -> Direction -> IO AESCtx
newECBCtx (toKey -> key) dir = wrapCtr =<< newECBCtx' key dir

newECBCtx' :: AESKey -> Direction -> IO Context
newECBCtx' key Encrypt = ECBCtx . EncryptCtx <$> encryptCtx key
newECBCtx' key Decrypt = ECBCtx . DecryptCtx <$> decryptCtx key

-- | Incrementally encrypt/decrypt bytestrings
--
-- crypt is definitely not thread-safe. Don't even think about
-- it.
crypt :: AESCtx -> B.ByteString -> IO B.ByteString
crypt (AESCtx ctx count) bs = do
  before <- readIORef count
  let blocks = ((before + B.length bs) `div` 16) - (before `div` 16)
      bytes = blocks * 16
  writeIORef count (before + bytes)
  crypt' ctx bs bytes

crypt' :: Context -> B.ByteString -> Int -> IO B.ByteString
crypt' (ECBCtx (EncryptCtx ctx))    = call _aes_ecb_encrypt ctx
crypt' (ECBCtx (DecryptCtx ctx))    = call _aes_ecb_decrypt ctx
crypt' (CBCCtx iv (EncryptCtx ctx)) = calliv _aes_cbc_encrypt iv ctx
crypt' (CBCCtx iv (DecryptCtx ctx)) = calliv _aes_cbc_decrypt iv ctx
crypt' (CFBCtx iv Encrypt ctx)      = calliv _aes_cfb_encrypt iv ctx
crypt' (CFBCtx iv Decrypt ctx)      = calliv _aes_cfb_decrypt iv ctx
crypt' (OFBCtx iv ctx)              = calliv _aes_ofb_crypt iv ctx
crypt' (CTRCtx iv ctx)              = aes_ctr_crypt iv ctx

call :: (Ptr b -> Ptr Word8 -> Int -> Ptr a -> IO Int)
       -> ForeignPtr a -> B.ByteString -> Int -> IO B.ByteString
call f ctx (BI.toForeignPtr -> (bs,offset,len)) retLen =
  withForeignPtr ctx $ \ctxp ->
  withForeignPtr bs $ \bsp ->
  BI.create retLen $ \obuf ->
  ensure $ f (bsp `plusPtr` offset) obuf len ctxp

calliv :: (Ptr b -> Ptr Word8 -> Int -> Ptr Word8 -> Ptr a -> IO Int)
         -> IV -> ForeignPtr a -> B.ByteString -> Int -> IO B.ByteString
calliv (addiv -> f) (IV iv) ctx bs retLen =
  withForeignPtr iv $ \ivp ->
  call (f ivp) ctx bs retLen

addiv :: (t1 -> t2 -> t3 -> t -> t4 -> t5) -> t -> t1 -> t2 -> t3 -> t4 -> t5
addiv f iv ibuf obuf len ctx = f ibuf obuf len iv ctx

aes_ctr_crypt :: IV -> EncryptCtxP -> B.ByteString -> Int -> IO B.ByteString
aes_ctr_crypt (IV ctr) ctx (BI.toForeignPtr -> (bs,offset,len)) retLen =
  withForeignPtr ctx $ \ctxp ->
  withForeignPtr bs $ \bsp ->
  withForeignPtr ctr $ \ctrp ->
  BI.create retLen $ \obuf ->
  ensure $ _aes_ctr_crypt (bsp `plusPtr` offset) obuf len ctrp _ctr_inc ctxp

foreign import ccall unsafe "aes_ecb_encrypt" _aes_ecb_encrypt
  :: Ptr Word8 -> Ptr Word8 -> Int -> Ptr EncryptCtxStruct -> IO Int
foreign import ccall unsafe "aes_ecb_decrypt" _aes_ecb_decrypt
  :: Ptr Word8 -> Ptr Word8 -> Int -> Ptr DecryptCtxStruct -> IO Int
foreign import ccall unsafe "aes_cbc_encrypt" _aes_cbc_encrypt
  :: Ptr Word8 -> Ptr Word8 -> Int -> Ptr Word8 -> Ptr EncryptCtxStruct -> IO Int
foreign import ccall unsafe "aes_cbc_decrypt" _aes_cbc_decrypt
  :: Ptr Word8 -> Ptr Word8 -> Int -> Ptr Word8 -> Ptr DecryptCtxStruct -> IO Int
foreign import ccall unsafe "aes_cfb_encrypt" _aes_cfb_encrypt
  :: Ptr Word8 -> Ptr Word8 -> Int -> Ptr Word8 -> Ptr EncryptCtxStruct -> IO Int
foreign import ccall unsafe "aes_cfb_decrypt" _aes_cfb_decrypt
  :: Ptr Word8 -> Ptr Word8 -> Int -> Ptr Word8 -> Ptr EncryptCtxStruct -> IO Int
foreign import ccall unsafe "aes_ofb_crypt" _aes_ofb_crypt
  :: Ptr Word8 -> Ptr Word8 -> Int -> Ptr Word8 -> Ptr EncryptCtxStruct -> IO Int
foreign import ccall unsafe "aes_ctr_crypt" _aes_ctr_crypt
  :: Ptr Word8 -> Ptr Word8 -> Int -> Ptr Word8 -> FunPtr (Ptr Word8 -> IO ()) -> Ptr EncryptCtxStruct -> IO Int
foreign import ccall unsafe "&ctr_inc" _ctr_inc :: FunPtr (Ptr Word8 -> IO ())

type EncryptCtxP = ForeignPtr EncryptCtxStruct

type DecryptCtxP = ForeignPtr DecryptCtxStruct

data EncryptCtxStruct
instance Storable EncryptCtxStruct where
  sizeOf _ = #size aes_encrypt_ctx
  alignment _ = 16 -- FIXME: Maybe overkill, maybe underkill, definitely iffy

data DecryptCtxStruct
instance Storable DecryptCtxStruct where
  sizeOf _ = #size aes_decrypt_ctx
  alignment _ = 16

wrap :: Int -> Bool
wrap r | r == (#const EXIT_SUCCESS) = True
       | otherwise = False

ensure :: IO Int -> IO ()
ensure act = do
  r <- wrap <$> act
  unless r (fail "AES function failed")

foreign import ccall unsafe "aes_encrypt_key" _aes_encrypt_key 
  :: Ptr Word8 -> Int -> Ptr EncryptCtxStruct -> IO Int

encryptCtx :: AESKey -> IO EncryptCtxP
encryptCtx (AESKey bs) = do
  ctx <- mallocForeignPtr
  let (key,offset,len) = BI.toForeignPtr bs
  withForeignPtr ctx $ \ctx' ->
    withForeignPtr key $ \key' ->
    ensure $ _aes_encrypt_key (key' `plusPtr` offset) len ctx'
  return ctx

foreign import ccall unsafe "aes_decrypt_key" _aes_decrypt_key 
  :: Ptr Word8 -> Int -> Ptr DecryptCtxStruct -> IO Int

decryptCtx :: AESKey -> IO DecryptCtxP
decryptCtx (AESKey bs) = do
  ctx <- mallocForeignPtr
  let (key,offset,len) = BI.toForeignPtr bs
  withForeignPtr ctx $ \ctx' ->
    withForeignPtr key $ \key' ->
    ensure $ _aes_decrypt_key (key' `plusPtr` offset) len ctx'
  return ctx
