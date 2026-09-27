
# Password Similarity Detection Using Bloom Filters

Python-based cybersecurity project that detects passwords similar to known password datasets using Bloom filters, cryptographic hashing, bigram analysis, and multiple similarity metrics.

## Features

* Password length validation
* Bigram-based password analysis
* Bloom filter construction
* SHA-256 and MD5 hashing
* Jaccard similarity
* Dice similarity
* Cosine similarity
* Combined similarity scoring
* Threshold-based password classification

## Technologies Used

* Python
* Bloom Filters
* SHA-256
* MD5
* Bigram Analysis
* Jaccard Similarity
* Dice Similarity
* Cosine Similarity

## How It Works

1. The candidate password is validated based on length requirements.
2. The password is divided into overlapping bigrams.
3. Each bigram is converted into a Bloom filter using cryptographic hash functions.
4. The individual Bloom filters are combined into a password representation.
5. The candidate password is compared against passwords in the dataset.
6. Jaccard, Dice, and Cosine similarity scores are calculated.
7. The scores are combined to produce an overall similarity score.
8. Passwords exceeding the defined similarity threshold are classified as rejected.

## Similarity Threshold

The project uses a similarity threshold of `0.75`.

* Score >= 0.75 → Rejected
* Score < 0.75 → Accepted

## Project Structure

```text
Password-Similarity-Bloom-Filters/
├── password_similarity.py
├── README.md
└── .gitignore
```

## Purpose

The project demonstrates how Bloom filters and cryptographic hashing can be applied to password security and similarity detection. It also demonstrates the use of multiple similarity metrics to compare password representations.

## Security Note

The project is intended for educational and research purposes. Real password datasets should not be uploaded to public repositories. Password datasets used during testing should be stored locally and excluded using `.gitignore`.
