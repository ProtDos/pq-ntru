# Quantum-Proof NTRU Algorithm

![License](https://img.shields.io/badge/license-Apache-blue.svg) ![Python](https://img.shields.io/badge/python-3.6%2B-brightgreen.svg) ![Version](https://img.shields.io/badge/version-1.0.0-orange.svg)

## Overview

Welcome to the NTRUEncrypt implementation, a robust lattice-based public key encryption scheme designed to withstand potential quantum computer attacks. This implementation uses the **NTRU Prime 4591** parameter set, offering an estimated security level of up to **256 bits**. Our goal is to provide a secure encryption solution for sensitive data in the age of quantum computing.

## 🚀 Getting Started

### Requirements

Ensure you have Python version **3.6 or higher** installed. You can check your Python version by running:

```bash
python --version
```

To install the necessary packages, use the following command:

```bash
pip install -r requirements.txt
```

Make sure to install `sympy` version **1.10** as specified in the `requirements.txt` file.

### Installation

Clone the repository to your local machine:

```bash
git clone https://github.com/protdos/pq-ntru
cd pq-ntru
```

## 🔑 Usage

After cloning the repository, you can import the NTRU module and utilize the `encrypt` and `decrypt` functions to securely encrypt and decrypt messages.

```python
from ntru import generate_keys, encrypt, decrypt

generate_keys("key", mode="moderate", skip_check=False, debug=True, check_time=True)

enc = encrypt("key", "test", check_time=True)
print("Encrypted message:", enc)

dec = decrypt("key", enc, check_time=True)
print("Decrypted message:", dec)
```

### Optional Parameters
- The first param is the filename of the keys generated.
- **skip_check**: Set to `True` to skip the security checks. More information on that down below.
- **debug**: Set to `True` to enable debug mode for verbose logging during encryption and decryption processes.
- **check_time**: Set to `True` to time the execution of encryption and decryption, allowing you to monitor performance.

The `mode` parameter gives the different paramteter sets. View them below:
```
PARAM_SETS = {
    "moderate": {"N": 107, "p": 3, "q": 64, "df": 15, "dg": 12, "d": 5},  # the key generation for this takes around 0.5sec
    "high": {"N": 167, "p": 3, "q": 128, "df": 61, "dg": 20, "d": 18},  # the key generation for this takes around 1.4sec
    "highest": {"N": 503, "p": 3, "q": 256, "df": 216, "dg": 72, "d": 55},  # the key generation for this takes around 15sec

    "dead": {"N": 701, "p": 3, "q": 8192, "df": 216, "dg": 72, "d": 55},  # the key generation for this takes around 50sec
    "dead2": {"N": 821, "p": 3, "q": 4096, "df": 216, "dg": 72, "d": 55},  # the key generation for this takes around 64sec
}
```

## 🔍 Implementation Details

This implementation adheres to the NTRU Prime 4591 parameter set, employing a polynomial ring with coefficients in the finite field **Z/4591Z**. 

### Encryption Steps

1. **Message Conversion**: Convert the message into a polynomial with coefficients in the range \([-1, 1]\).
2. **Random Polynomial Generation**: Generate a random polynomial within the same coefficient range and compute its inverse modulo a predetermined polynomial.
3. **Polynomial Multiplication**: Calculate the product of the message polynomial and the inverse polynomial modulo the specific polynomial, yielding a new polynomial.
4. **Ciphertext Generation**: Add noise to the new polynomial to produce the ciphertext polynomial.

### Decryption Steps

- Compute the product of the ciphertext polynomial and the private key polynomial modulo the designated polynomial to obtain a new polynomial.
- Recover the original message polynomial by calculating the inverse of the resulting polynomial modulo the predetermined polynomial.

## 🛡️ Security Checks

This implementation includes a feature to verify the security of generated keys. The checks performed are:

- Ensuring `h[-1]` has no factors.
- Verifying that the total number of possible keys exceeds \(2^{80}\).
- Confirming that `f` contains a sufficient number of non-zero coefficients.
- Validating that `h` contains a sufficient number of non-zero coefficients.

These security checks are based on the [Wikipedia entry on NTRU](https://en.wikipedia.org/wiki/NTRUEncrypt#Attacks), ensuring that the keys are generated securely.

### Parameters

The following [secure parameters](https://en.wikipedia.org/wiki/NTRUEncrypt#Table_1:_Parameters) have been disclosed by [NIST](https://www.nist.gov/):

| Security Level                 | N   | q    | p |
|--------------------------------|-----|------|---|
| **128-bit security margin**    | 509 | 2048 | 3 |
| **192-bit security margin**    | 677 | 2048 | 3 |
| **256-bit security margin**    | 821 | 4096 | 3 |
| **256-bit security margin (HRSS)** | 701 | 8192 | 3 |

- `N` is the order of the polynomial ring, 
- `p` is the modulus of the polynomial f (which has df 1 coefficients and df-1 -1 coefficients), 
- `q` is the modulus of the polynomial g (which has dg 1 and -1 coefficients),
- `d` is the number of 1 and -1 coefficients in the obfuscating polynomial.

## 🚀 Performance
Multiple functions have been improved to increase the performance, speed and efficiency. Examples are: `check_prime()`, `inv_poly()`.


## 📚 Basic Information on NTRU

NTRUEncrypt operates on the mathematical problem of finding short vectors in a lattice, making it a strong candidate against quantum computing attacks due to its lattice-based cryptography. The security relies on the difficulty of identifying short vectors within a lattice, a problem believed to remain challenging even for quantum systems.

### History

NTRU was first introduced in **1996** by **Hoffstein, Pipher, and Silverman**. Various variants have since been developed, including **NTRUEncrypt** for public key encryption and **NTRU Signature** for digital signatures.

## 🏆 Benefits of NTRU

NTRUEncrypt offers several advantages over traditional public key cryptosystems:

- **Quantum Resistance**: Designed to be resilient against quantum attacks.
- **Performance**: High efficiency compared to conventional algorithms.
- **Compact Key Sizes**: Smaller keys without compromising security.
- **Low Bandwidth Usage**: Efficient in terms of data transmission.
- **Robust Against Side-Channel Attacks**: Enhanced security features to counteract potential vulnerabilities.

## 🤝 Contributing

We welcome contributions to enhance this project! If you would like to contribute, please follow these steps:

1. **Fork the repository** on GitHub.
2. **Create a new branch** for your feature or bug fix:
   ```bash
   git checkout -b feature/YourFeatureName
   ```
3. **Make your changes** and commit them:
   ```bash
   git commit -m "Add a feature"
   ```
4. **Push to your fork**:
   ```bash
   git push origin feature/YourFeatureName
   ```
5. **Create a pull request** on GitHub.

Please ensure that your code adheres to our coding standards and includes appropriate tests.

## 📜 License

This project is licensed under the **Apache License**. See the [LICENSE](LICENSE) file for details.

---

Feel free to reach out for any inquiries or contributions. Your feedback is valuable!
