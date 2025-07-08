"""
zokrates_interface.py

Provides an interface for generating and verifying zero-knowledge proofs (ZKPs) using ZoKrates, both in simulation and via CLI commands

- Simulates ZKP generation by hashing OTP and timestamp.
- Provides wrapper functions to compile ZoKrates circuits, set up keys, compute witnesses, generate proofs, and verify proofs using the ZoKrates CLI.
- Designed to be used by Vehicle and RSU classes for proof generation and verification.
"""

import subprocess
import os

DEBUG_MODE = False

"""Enable or disable debug mode for detailed output"""
def set_debug_mode(enabled):
    global DEBUG_MODE
    DEBUG_MODE = enabled

"""Remove ZoKrates-generated files from the current directory"""
def cleanup_zokrates_files():
    
    files_to_remove = [
        "out",
        "out.r1cs",
        "out.wtns",
        "proving.key",
        "verification.key",
        "witness",
        "proof.json",
        "abi.json"
    ]
    
    for filename in files_to_remove:
        
        if os.path.exists(filename):
            
            os.remove(filename)
            
            if DEBUG_MODE:
                print(f"Removed {filename}")

"""
Compile a ZoKrates circuit file

Args:
circuit_path (str): Path to the ZoKrates .zok circuit file
    
Returns:
bool: True if compilation succeeds, False otherwise
"""
def run_zokrates_compile(circuit_path):
    
    try:
        
        # Run the ZoKrates compile command with the given circuit file
        result = subprocess.run(
            ["zokrates", "compile", "-i", circuit_path],
            capture_output=True, text=True, check=True
        )
        
        if DEBUG_MODE:
            print("ZoKrates compile output:", result.stdout)
            
        return True
    
    except Exception as e:
        
        if DEBUG_MODE:
            print("ZoKrates compile failed:", e)
            
        return False


"""
Run ZoKrates setup to generate proving and verification keys

Returns:
bool: True if setup succeeds, False otherwise
"""
def run_zokrates_setup():
    
    try:
        
        # Run the ZoKrates setup command
        result = subprocess.run(
            ["zokrates", "setup"],
            capture_output=True, text=True, check=True
        )
        
        if DEBUG_MODE:
            print("ZoKrates setup output:", result.stdout)
            
        return True
    
    except Exception as e:
        
        if DEBUG_MODE:
            print("ZoKrates setup failed:", e)
            
        return False


"""
Compute the witness for a ZoKrates circuit

Args:
args (list of str): Arguments to pass to the circuit (e.g., private/public inputs)
    
Returns:
bool: True if witness computation succeeds, False otherwise
"""
def run_zokrates_compute_witness(args):
    
    try:
        
        # Run the ZoKrates compute-witness command
        result = subprocess.run(
            ["zokrates", "compute-witness", "-a"] + args,
            capture_output=True, text=True, check=True
        )

        if DEBUG_MODE:
            
            print("ZoKrates compute-witness output:", result.stdout)
            
        return True
    
    except Exception as e:
        
        if DEBUG_MODE:
            print("ZoKrates compute-witness failed:", e)
            
        return False


"""
Generate a ZoKrates proof using the computed witness and setup keys

Returns:
bool: True if proof generation succeeds, False otherwise
"""
def run_zokrates_generate_proof():
    
    try:
        
        # Run the ZoKrates generate-proof command
        result = subprocess.run(
            ["zokrates", "generate-proof"],
            capture_output=True, text=True, check=True
        )
        
        if DEBUG_MODE:
            print("ZoKrates generate-proof output:", result.stdout)
            
        return True
    
    except Exception as e:
        
        if DEBUG_MODE:
            print("ZoKrates generate-proof failed:", e)
            
        return False


"""
Verify a ZoKrates proof using the verification key

Returns:
bool: True if the proof is valid, False otherwise
"""
def run_zokrates_verify():
    
    try:
        
        # Run the ZoKrates verify command
        result = subprocess.run(
            ["zokrates", "verify"],
            capture_output=True, text=True, check=True
        )
        
        if DEBUG_MODE:
            print("ZoKrates verify output:", result.stdout)
            
        return ("Proof is valid" in result.stdout) or ("PASSED" in result.stdout)
    
    except Exception as e:
        
        if DEBUG_MODE:
            print("ZoKrates verify failed:", e)
            
        return False


if __name__ == "__main__":
    
    set_debug_mode(True)
    
    print("Compiling dummy.zok...")
    dummy_zok_path = os.path.join("dummy.zok")
    
    if not run_zokrates_compile(dummy_zok_path):
        print("Compilation failed.")
        exit(1)
        
    print("Running setup...")
    
    if not run_zokrates_setup():
        print("Setup failed.")
        exit(1)
        
    print("Computing witness...")
    
    if not run_zokrates_compute_witness(["3", "4"]):
        print("Compute witness failed.")
        exit(1)
        
    print("Generating proof...")
    
    if not run_zokrates_generate_proof():
        print("Generate proof failed.")
        exit(1)
        
    print("Verifying proof...")
    
    if run_zokrates_verify():
        
        print("Proof is valid! Communication with ZoKrates works.")
        
        cleanup_zokrates_files()
        
    else:
        print("Proof is invalid or verification failed.")

