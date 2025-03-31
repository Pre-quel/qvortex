"""
Python wrapper for the Qvortex Hash Algorithm

This module provides Python bindings to the Qvortex hash function
implemented in C. It detects the appropriate shared library extension
based on the current platform.
"""

import os
import sys
import platform
import ctypes
from ctypes import c_int, c_size_t, c_uint8, POINTER
from typing import Optional, Union, ByteString

# Detect platform and set library extension
if platform.system() == "Darwin":  # macOS
    DEFAULT_LIB_NAME = "libqvortex.dylib"
elif platform.system() == "Windows":
    DEFAULT_LIB_NAME = "qvortex.dll"
else:  # Linux or other Unix-like
    DEFAULT_LIB_NAME = "libqvortex.so"

class QvortexError(Exception):
    """Exception raised for Qvortex hash errors"""
    pass

class QvortexContext:
    """
    Wrapper for the Qvortex context structure
    
    This class should match the C structure layout:
    typedef struct {
      uint64_t state[8];
      uint8_t sbox[256];
      uint8_t buffer[64];
      size_t buffer_len;
      uint64_t total_len;
    } qvortex_lite_ctx;
    """
    _fields_ = [
        ("state", c_uint8 * 64),         # 8 uint64_t values = 64 bytes
        ("sbox", c_uint8 * 256),         # 256 bytes for S-box
        ("buffer", c_uint8 * 64),        # 64 bytes for block buffer
        ("buffer_len", c_size_t),        # size_t for buffer length
        ("total_len", c_uint8 * 8)       # uint64_t for total length
    ]

class QvortexHash:
    """
    Python wrapper for the Qvortex hash algorithm
    
    This class provides access to the Qvortex hash function implemented in C.
    It supports both one-shot hashing and incremental updates.
    """
    
    def __init__(self, library_path: Optional[str] = None, key: Optional[bytes] = None):
        """
        Initialize the QvortexHash wrapper
        
        Args:
            library_path: Path to the Qvortex shared library (default: auto-detect)
            key: Optional key for keyed hashing
        
        Raises:
            QvortexError: If the library cannot be loaded
        """
        # Load the shared library
        if library_path is None:
            # Look in current directory first
            if os.path.exists(DEFAULT_LIB_NAME):
                library_path = DEFAULT_LIB_NAME
            else:
                # Try to find in the same directory as this script
                script_dir = os.path.dirname(os.path.abspath(__file__))
                library_path = os.path.join(script_dir, DEFAULT_LIB_NAME)
                
                # If not found, use just the name and let the loader find it
                if not os.path.exists(library_path):
                    library_path = DEFAULT_LIB_NAME
        
        try:
            self.lib = ctypes.CDLL(library_path)
        except OSError as e:
            raise QvortexError(f"Failed to load Qvortex library: {e}")
        
        # Define function prototypes
        self._define_functions()
        
        # Store the key
        self.key = key
        if key is not None and not isinstance(key, bytes):
            if isinstance(key, str):
                self.key = key.encode('utf-8')
            else:
                self.key = bytes(key)

    def _define_functions(self):
        """Define the C function prototypes"""
        # One-shot hash function
        self.lib.qvortex_hash.argtypes = [
            POINTER(c_uint8),  # data
            c_size_t,          # len
            c_int,             # blocks_per_sbox
            c_int,             # use_precomputed
            POINTER(c_uint8),  # key
            c_size_t,          # key_len
            POINTER(c_uint8)   # out
        ]
        self.lib.qvortex_hash.restype = c_int
        
        # Alternative name for backward compatibility
        self.lib.vortex_hash = self.lib.qvortex_hash
        
        # Incremental API
        self.lib.qvortex_init.argtypes = [
            ctypes.c_void_p,   # ctx
            POINTER(c_uint8),  # key
            c_size_t           # key_len
        ]
        self.lib.qvortex_init.restype = c_int
        
        self.lib.qvortex_update.argtypes = [
            ctypes.c_void_p,   # ctx
            POINTER(c_uint8),  # data
            c_size_t           # len
        ]
        self.lib.qvortex_update.restype = c_int
        
        self.lib.qvortex_final.argtypes = [
            ctypes.c_void_p,   # ctx
            POINTER(c_uint8)   # out
        ]
        self.lib.qvortex_final.restype = c_int
        
        # Version info
        self.lib.qvortex_version.argtypes = []
        self.lib.qvortex_version.restype = ctypes.c_char_p
    
    def hash(self, data: Union[bytes, bytearray, str], 
             key: Optional[bytes] = None) -> bytes:
        """
        Compute the Qvortex hash of the input data
        
        Args:
            data: Input data to hash
            key: Optional key for keyed hashing (overrides the one set in constructor)
        
        Returns:
            bytes: 64-byte Qvortex hash digest
        
        Raises:
            QvortexError: If hashing fails
        """
        # Convert string to bytes if needed
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # Use the provided key or the default one
        use_key = key if key is not None else self.key
        
        # Prepare data buffer
        data_len = len(data)
        data_buf = (c_uint8 * data_len)(*data)
        
        # Prepare output buffer (64 bytes)
        out_buf = (c_uint8 * 64)()
        
        # Prepare key buffer if needed
        key_ptr = None
        key_len = 0
        
        if use_key:
            if isinstance(use_key, str):
                use_key = use_key.encode('utf-8')
            key_len = len(use_key)
            key_buf = (c_uint8 * key_len)(*use_key)
            key_ptr = key_buf
        
        # Call the hash function
        result = self.lib.qvortex_hash(
            data_buf if data_len > 0 else None,
            data_len,
            1,                 # blocks_per_sbox (not used)
            0,                 # use_precomputed (not used)
            key_ptr,
            key_len,
            out_buf
        )
        
        # Check for errors
        if result != 0:
            raise QvortexError(f"Qvortex hash function failed with error code {result}")
        
        # Convert output buffer to bytes
        return bytes(out_buf)
    
    class HashContext:
        """Context manager for incremental hashing"""
        
        def __init__(self, qvortex_instance, key=None):
            self.qvortex = qvortex_instance
            self.key = key
            
            # Allocate memory for the context structure
            # We're using raw memory allocation since ctypes doesn't handle complex structs well
            self.ctx = ctypes.create_string_buffer(1024)  # More than enough space
            
            # Initialize the context
            key_ptr = None
            key_len = 0
            
            if key:
                if isinstance(key, str):
                    key = key.encode('utf-8')
                key_len = len(key)
                key_buf = (c_uint8 * key_len)(*key)
                key_ptr = key_buf
            
            result = self.qvortex.lib.qvortex_init(
                self.ctx,
                key_ptr,
                key_len
            )
            
            if result != 0:
                raise QvortexError(f"Failed to initialize Qvortex context: {result}")
        
        def update(self, data):
            """Update the hash context with more data"""
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            data_len = len(data)
            if data_len == 0:
                return
                
            data_buf = (c_uint8 * data_len)(*data)
            
            result = self.qvortex.lib.qvortex_update(
                self.ctx,
                data_buf,
                data_len
            )
            
            if result != 0:
                raise QvortexError(f"Failed to update Qvortex context: {result}")
        
        def digest(self):
            """Finalize and return the digest"""
            out_buf = (c_uint8 * 64)()
            
            result = self.qvortex.lib.qvortex_final(
                self.ctx,
                out_buf
            )
            
            if result != 0:
                raise QvortexError(f"Failed to finalize Qvortex context: {result}")
            
            return bytes(out_buf)
    
    def new(self, key=None):
        """Create a new hash context for incremental updates"""
        return self.HashContext(self, key or self.key)
    
    @property
    def version(self) -> str:
        """Get the version of the Qvortex library"""
        version_bytes = self.lib.qvortex_version()
        return version_bytes.decode('utf-8')

# Create a global instance with default settings
try:
    qvortex = QvortexHash()
except QvortexError:
    qvortex = None

def hash(data, key=None):
    """
    Convenience function to compute a Qvortex hash
    
    Args:
        data: Input data to hash
        key: Optional key for keyed hashing
    
    Returns:
        bytes: 64-byte Qvortex hash digest
    
    Raises:
        QvortexError: If the library is not available or hashing fails
    """
    if qvortex is None:
        raise QvortexError("Qvortex library not available")
    return qvortex.hash(data, key)

# Example usage
if __name__ == "__main__":
    # Simple test to verify the wrapper works
    try:
        # Test with global instance
        data = b"Hello, world!"
        h1 = hash(data)
        print(f"Qvortex({data.decode()}) = {h1.hex()}")
        
        # Test with keyed hashing
        key = b"test key"
        h2 = hash(data, key)
        print(f"Qvortex({data.decode()}, key='{key.decode()}') = {h2.hex()}")
        
        # Test incremental hashing
        ctx = qvortex.new()
        ctx.update("Hello, ")
        ctx.update("world!")
        h3 = ctx.digest()
        print(f"Incremental Qvortex('Hello, world!') = {h3.hex()}")
        
        # Verify results match
        print(f"h1 == h3: {h1 == h3}")
        
        print(f"Qvortex version: {qvortex.version}")
        
    except QvortexError as e:
        print(f"Error: {e}")
        print("Make sure the Qvortex library is properly installed.")
