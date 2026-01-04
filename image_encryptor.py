
from typing import Tuple
import argparse
import hashlib
import random

from PIL import Image
import numpy as np


def derive_key(password: str) -> Tuple[bytes, int]:
    """
    Derive a fixed-length byte key and an integer seed from the given password.
    We use SHA-256 so any password length becomes a deterministic 32-byte value.
    """
    digest = hashlib.sha256(password.encode("utf-8")).digest()  # 32 bytes
    seed = int.from_bytes(digest, byteorder="big")
    return digest, seed


def load_image_as_array(path: str) -> Tuple[np.ndarray, str]:
    """Load image and return numpy array (dtype=uint8) and mode string."""
    img = Image.open(path)
    mode = img.mode  # e.g., "RGB", "RGBA", "L"
    arr = np.array(img, dtype=np.uint8)
    return arr, mode


def save_array_as_image(arr: np.ndarray, mode: str, path: str) -> None:
    """Save numpy array (uint8) back to an image file."""
    img = Image.fromarray(arr, mode=mode)
    img.save(path)


def xor_cipher(arr: np.ndarray, key_bytes: bytes) -> np.ndarray:
    """
    XOR every byte in the image array with repeated key bytes.
    This operation is symmetric: applying it twice with same key returns original.
    """
    flat = arr.ravel()  # 1-D view of bytes
    key_stream = np.frombuffer(key_bytes, dtype=np.uint8)
    # Repeat key stream to the length of flat
    reps = (flat.size + key_stream.size - 1) // key_stream.size
    repeated = np.tile(key_stream, reps)[: flat.size]
    result = np.bitwise_xor(flat, repeated).astype(np.uint8)
    return result.reshape(arr.shape)


def _get_pixel_permutation(n_pixels: int, seed: int) -> np.ndarray:
    """Return a permutation of indices [0..n_pixels-1] generated deterministically from seed."""
    rng = random.Random(seed)
    indices = list(range(n_pixels))
    rng.shuffle(indices)
    return np.array(indices, dtype=np.int64)


def shuffle_pixels(arr: np.ndarray, seed: int) -> np.ndarray:
    """
    Shuffle pixel positions deterministically using seed.
    We treat each pixel as a unit (all channels move together).
    """
    h_w = arr.shape[0] * arr.shape[1]
    # Flatten to (n_pixels, channels)
    flat = arr.reshape(h_w, -1)
    perm = _get_pixel_permutation(h_w, seed)
    shuffled = flat[perm]
    return shuffled.reshape(arr.shape)


def unshuffle_pixels(arr: np.ndarray, seed: int) -> np.ndarray:
    """
    Reverse the shuffle: compute the same permutation and invert it.
    """
    h_w = arr.shape[0] * arr.shape[1]
    flat = arr.reshape(h_w, -1)
    perm = _get_pixel_permutation(h_w, seed)
    inv = np.empty_like(perm)
    inv[perm] = np.arange(h_w, dtype=np.int64)
    unshuffled = flat[inv]
    return unshuffled.reshape(arr.shape)


def encrypt_image(
    input_path: str, output_path: str, password: str, method: str = "both"
) -> None:
    arr, mode = load_image_as_array(input_path)
    key_bytes, seed = derive_key(password)

    if method == "xor":
        out = xor_cipher(arr, key_bytes)
    elif method == "shuffle":
        out = shuffle_pixels(arr, seed)
    elif method == "both":
        # XOR first, then shuffle
        xored = xor_cipher(arr, key_bytes)
        out = shuffle_pixels(xored, seed)
    else:
        raise ValueError("Unknown method")

    save_array_as_image(out, mode, output_path)
    print(f"Encrypted ({method}) saved to: {output_path}")


def decrypt_image(
    input_path: str, output_path: str, password: str, method: str = "both"
) -> None:
    arr, mode = load_image_as_array(input_path)
    key_bytes, seed = derive_key(password)

    if method == "xor":
        out = xor_cipher(arr, key_bytes)  # XOR is symmetric
    elif method == "shuffle":
        out = unshuffle_pixels(arr, seed)
    elif method == "both":
        # Unshuffle first, then XOR
        unshuffled = unshuffle_pixels(arr, seed)
        out = xor_cipher(unshuffled, key_bytes)
    else:
        raise ValueError("Unknown method")

    save_array_as_image(out, mode, output_path)
    print(f"Decrypted ({method}) saved to: {output_path}")


def parse_args():
    p = argparse.ArgumentParser(description="Simple image encryptor using pixel operations.")
    p.add_argument("--mode", required=True, choices=["encrypt", "decrypt"], help="encrypt or decrypt")
    p.add_argument("--method", choices=["xor", "shuffle", "both"], default="both", help="Operation method")
    p.add_argument("--key", required=True, help="Password/key (string). Must be same for encrypt/decrypt")
    p.add_argument("--input", required=True, help="Input image path")
    p.add_argument("--output", required=True, help="Output image path")
    return p.parse_args()


def main():
    args = parse_args()
    if args.mode == "encrypt":
        encrypt_image(args.input, args.output, args.key, args.method)
    else:
        decrypt_image(args.input, args.output, args.key, args.method)


if __name__ == "__main__":
    main()