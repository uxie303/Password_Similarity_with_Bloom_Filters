# -*- coding: utf-8 -*-

"""
Text Processing & Bigram Breakdown
:
- Password input validation
- String preprocessing (padding)
- Bigram extraction
- Atom vector initialization

"""

import hashlib
import math

BLOOM_SIZE = 1000
NUM_HASHES = 20

def sha256_int(text):
    return int(hashlib.sha256(text.encode("utf-8")).hexdigest(), 16)


def md5_int(text):
    return int(hashlib.md5(text.encode("utf-8")).hexdigest(), 16)


def hash_position(f, g, i):
    return (f + i * g) % BLOOM_SIZE


def build_atom(bigram):
    # normalize (important for consistency)
    bigram = bigram.upper()

    atom = [0] * BLOOM_SIZE

    f = sha256_int(bigram)
    g = (md5_int(bigram) % BLOOM_SIZE) or 1

    for i in range(NUM_HASHES):
        pos = hash_position(f, g, i)
        atom[pos] = 1

    return atom

#
#  1: PASSWORD VALIDATION
#

def validate_password(password):

    ## Validate password length constraint (8-10 characters).

    return isinstance(password, str) and 8 <= len(password) <= 10


def get_password_with_validation():

    #Get password from user and validate it.


    password = input("Enter password: ")

    if not isinstance(password, str):
        return password, False, "ERROR: Password must be text"

    if len(password) < 8:
        error = f"Password too short. (need 8-10)"
        return password, False, error

    if len(password) > 10:
        error = f"Password too long. (need 8-10)"
        return password, False, error

    return password, True, ""


def display_password_validation(password, is_valid, error_message):
    """
    Display formatted validation result.

    Args:
        password (str): Password checked
        is_valid (bool): True if valid
        error_message (str): Error reason (empty if valid)
    """
    print("\n" + "="*60)
    print("PASSWORD VALIDATION RESULT")
    print("="*60)
    print(f"Password entered: '{password}'")
    print(f"Length: {len(password)} characters")
    print()

    if is_valid:

        print(" Password meets requirements (8-10 characters)")
    else:

        print(f" status failed. Reason: {error_message}")

    print("="*60 + "\n")


#
#  # 2: STRING PREPROCESSING
#

def preprocess_password(password):
    """
    Add space padding to beginning and end of password.
    needed for proper bigram extraction ('cause boundary characters).

    """
    return " " + password + " "


#
#  # 3: BIGRAM EXTRACTION
#

def extract_bigrams(padded_password):
    """
    Extract all 2-character consecutive bigrams [ sliding window.]
     1 character each iteration (overlapping).

    Example:
        " MUELLER " → [' M', 'MU', 'UE', 'EL', 'LL', 'LE', 'ER', 'R ']
    """
    bigrams = []

    for i in range(len(padded_password) - 1):
        bigram = padded_password[i:i+2]
        bigrams.append(bigram)

    return bigrams


#
#  # 4: ATOM VECTOR INITIALIZATION
#

def initialize_atom_vectors(bigrams):
    """
    Build Bloom-filter atoms for each bigram.
    """
    atoms = {}

    for bigram in bigrams:
        if bigram not in atoms:
            atoms[bigram] = build_atom(bigram)

    return atoms


def display_bloom_filter(beta, title="Bloom Filter"):
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)

    ones = sum(beta)
    density = ones / len(beta)

    print(f"Size        : {len(beta)} bits")
    print(f"Active bits : {ones}")
    print(f"Density     : {round(density * 100, 2)}%")
    print()

#
#  # 5: MAIN PIPELINE
#

def process_password_to_bigrams(password):
    """
     pipeline: validate → preprocess → extract bigrams → initialize atoms.

    """
    if not validate_password(password):
        return None

    padded = preprocess_password(password)
    bigrams = extract_bigrams(padded)
    atoms = initialize_atom_vectors(bigrams)

    return padded, bigrams, atoms


def main_validation_flow():

    ##Get password from user, validate, display result, extract bigrams.
    ##Loops until valid password entered !!!


    print("\n" + "="*60)
    print("PASSWORD VALIDATION MODULE")
    print("="*60)
    print("Requirements: Password must be 8-10 characters long")
    print("="*60 + "\n")

    while True:
        password, is_valid, error_message = get_password_with_validation()
        display_password_validation(password, is_valid, error_message)

        if is_valid:
            print("✓ Proceeding with bigram extraction...\n")
            result = process_password_to_bigrams(password)

            if result:
                padded, bigrams, atoms = result

                print("="*60)
                print("BIGRAM EXTRACTION RESULTS")
                print("="*60)
                print(f"✓ Bigram extraction successful")
                print(f"  Original password: '{password}'")
                print(f"  Padded password:   '{padded}'")
                print(f"  Number of bigrams: {len(bigrams)}")
                print(f"  Bigrams: {bigrams}")
                print(f"  Atoms initialized: {len(atoms)} unique bigrams")
                print(f"  Each atom size: 1000 bits")
                print("="*60 + "\n")

                return password, padded, bigrams, atoms

        print("Please try again.\n")


#
#  # 6: BLOOM FILTER CONSTRUCTION
#

def combine_atoms_to_beta(atoms):
    """
    Combine all atom vectors into one bloom filter.
    """
    beta = [0] * BLOOM_SIZE

    for bigram in atoms:
        atom = atoms[bigram]

        for i in range(BLOOM_SIZE):
            if atom[i] == 1:
                beta[i] = 1

    return beta


def build_bloom_filter(password):
    """
    Build beta(p) bloom filter for one password.
    """
    result = process_password_to_bigrams(password)

    if result is None:
        return None

    padded, bigrams, atoms = result
    beta = combine_atoms_to_beta(atoms)

    return beta


#
#  # 7: DATASET PRECOMPUTATION
#

def load_dataset(filename):
    """
    Read valid passwords from dataset.
    """
    passwords = []

    with open(filename, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            password = line.strip()

            if validate_password(password):
                passwords.append(password)

    return passwords


def precompute_dataset_filters(filename):
    """
    Store each dataset password with its bloom filter.
    """
    passwords = load_dataset(filename)
    dataset_filters = []

    for password in passwords:
        beta = build_bloom_filter(password)

        if beta is not None:
            dataset_filters.append((password, beta))

    return dataset_filters


#
# ENTRY POINT
#

#
# ENTRY POINT
#



# MEMBER 4: SIMILARITY METRICS ENGINE
def jaccard_similarity(vector_a, vector_b):
    """
    Computes Jaccard Coefficient between two Bloom filter bit vectors.
    Formula: |A ∩ B| / |A ∪ B|
    """
    intersection = sum(1 for a, b in zip(vector_a, vector_b) if a == 1 and b == 1)
    total_a = sum(vector_a)
    total_b = sum(vector_b)
    union = total_a + total_b - intersection
    if union == 0:
        return 0.0
    return intersection / union

def dice_coefficient(vector_a, vector_b):
    """
    Computes The Dice Coefficient between two Bloom filter bit vectors.
    Formula: 2 * |A ∩ B| / (|A| + |B|)
    """
    intersection = sum(1 for a, b in zip(vector_a, vector_b) if a == 1 and b == 1)
    total_a = sum(vector_a)
    total_b = sum(vector_b)
    if (total_a + total_b) == 0:
        return 0.0
    return (2.0 * intersection) / (total_a + total_b)

def cosine_similarity(vector_a, vector_b):
    """
    Computes The Cosine Similarity between two Bloom filter bit vectors.
    Formula: |A ∩ B| / sqrt(|A| * |B|)
    """
    intersection = sum(1 for a, b in zip(vector_a, vector_b) if a == 1 and b == 1)
    total_a = sum(vector_a)
    total_b = sum(vector_b)
    denominator = math.sqrt(total_a * total_b)
    if denominator == 0:
        return 0.0
    return intersection / denominator

#
#8: Application Controller (member 5)
#

SIMILARITY_THRESHOLD = 0.75

def best_match_finding(candidate_filter, dataset_filters):

    best_password = ""
    best_scores = {
        "jaccard": -1,
        "dice": -1,
        "cosine": -1
    }

    best_combo_score = -1  # optional combined ranking

    for password, bloom_filter in dataset_filters:

        j = jaccard_similarity(candidate_filter, bloom_filter)
        d = dice_coefficient(candidate_filter, bloom_filter)
        c = cosine_similarity(candidate_filter, bloom_filter)

        # choose ranking method (you can change this)
        combo = (j + d + c) / 3

        if combo > best_combo_score:
            best_combo_score = combo
            best_password = password
            best_scores = {
                "jaccard": j,
                "dice": d,
                "cosine": c
            }

    return best_password, best_scores


def classify_password(score):
  # here we decide whether tha password is to be accpeted or rejected

  if score >=SIMILARITY_THRESHOLD:
    return "REJECTED"
  else:
    return "ACCEPTED"


def check_password(candidate, dataset_filters):

    candidate_filter = build_bloom_filter(candidate)

    if candidate_filter is None:
        print("Invalid Password, password must be between 8 to 10 characters")
        return

    display_bloom_filter(candidate_filter, "Bloom Filter")

    match, scores = best_match_finding(candidate_filter, dataset_filters)

    decision = classify_password(
        (scores["jaccard"] + scores["dice"] + scores["cosine"]) / 3
    )

    print("\n" + "=" * 50)
    print("PASSWORD CHECK RESULT")
    print("=" * 50)
    print("Password Tested :", candidate)
    print("Closest Match   :", match)
    print("Jaccard Score   :", round(scores["jaccard"], 4))
    print("Dice Coeff      :", round(scores["dice"], 4))
    print("Cosine Sim      :", round(scores["cosine"], 4))
    print("Decision        :", decision)
    print("=" * 50)

def application_run():
  print("\nLoading password database...")

  dataset_filters= precompute_dataset_filters("rockyou_subset_34.txt")
  print("Database loaded")
  print("Passwords stored:", len(dataset_filters))

  while True:
    candidate=input("\nEnter a password (or type exit): ")

    if candidate.lower()=="exit":
      print("The program has ended")
      break

    check_password(candidate,dataset_filters)

if __name__=="__main__":
    application_run()

from google.colab import files
uploaded = files.upload()