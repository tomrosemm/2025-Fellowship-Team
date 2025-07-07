"""
preliminary_tests.py

Requires: vehicle.py, rsu.py, zokrates_interface.py, blockchain.py
Run this script directly to execute all tests and scenarios in testAndScenarioRunner()

This module contains test routines to simulate and validate the ZKP-OTP authentication protocol
between Vehicle and RSU entities. It demonstrates the authentication process using both simulated
and real (ZoKrates-based) zero-knowledge proof workflows, as well as a blockchain verification simulation,
currently not implemented with hardhat/similar, though it will eventually be

- Simulates the generation of one-time passwords (OTP) and timestamps by vehicles
- Demonstrates creation of zero-knowledge proofs (ZKP) for OTP and timestamp
- Shows verification of ZKPs by RSUs using both simulated (hash-based) and real ZoKrates CLI methods
- Includes a workflow for simulating blockchain-based verification and logging
- Provides functions for each workflow, which can be run directly for demonstration and prototyping

"""

import secrets
import os
import time
import random

from vehicle import Vehicle
from rsu import RSU
from zokrates_interface import (
    run_zokrates_compile,
    run_zokrates_setup,
    run_zokrates_compute_witness,
    run_zokrates_generate_proof,
    run_zokrates_verify,
    cleanup_zokrates_files,
    set_debug_mode as set_zokrates_debug_mode
)
from blockchain import simulate_blockchain_verification

# Track number of tests run and passed
tested = 0
passed = 0

DEBUG_MODE = False

"""Enable or disable debug mode"""
def set_debug_mode(enabled: bool):
    global DEBUG_MODE
    DEBUG_MODE = enabled
    set_zokrates_debug_mode(enabled)

"""Clears the console screen based on the operating system"""
def clear_console():
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')


"""Test the workflow using a simulated ZKP (hash-based)"""
def test_vehicle_rsu_interaction_simulated():
    
    print("\n=== Simulated ZKP Test ===")
    global tested, passed
    tested += 1
    
    # Generate entities
    vehicle_id = "VEH123"
    vehicle_secret = secrets.token_hex(16)
    vehicle = Vehicle(vehicle_id, vehicle_secret)
    rsu = RSU({vehicle_id: vehicle_secret})

    # Generate OTP and timestamp
    otp, timestamp = vehicle.generate_otp()
    if DEBUG_MODE:
        print(f"\n[Simulated] OTP: {otp}\n\nTimestamp: {timestamp}\n")
        
    # Create simulated ZKP proof
    zkp_proof = vehicle.create_zkp(otp, timestamp)
    if DEBUG_MODE:
        print(f"[Simulated] ZKP Proof: {zkp_proof}\n")

    # RSU verifies ZKP proof
    verification_result = rsu.verify_zkp(vehicle_id, zkp_proof, timestamp)
    if DEBUG_MODE:
        print(f"[Simulated] Verification result: {verification_result}\n")

    # Output authentication result
    if verification_result:
        passed += 1
        print("[Simulated] Vehicle authenticated. Session started.\n")
    else:
        print("[Simulated] Authentication failed.\n")


"""Simulate the full workflow, including using ZoKrates for the ZKP as well as blockchain verification and logging"""
def test_vehicle_rsu_blockchain_simulated():
    
    print("\n=== Simulated Blockchain ZKP Test ===")
    global tested, passed
    tested += 1
    
    # Generate entities
    vehicle_id = "VEH123"
    vehicle_secret = secrets.token_hex(16)
    vehicle = Vehicle(vehicle_id, vehicle_secret)
    rsu = RSU({vehicle_id: vehicle_secret})

    # Generate OTP and timestamp
    otp, timestamp = vehicle.generate_otp()
    if DEBUG_MODE:
        print(f"\n[Simulated] OTP: {otp}\n\nTimestamp: {timestamp}\n")

    # Create simulated ZKP proof
    zkp_proof = vehicle.create_zkp(otp, timestamp)
    if DEBUG_MODE:
        print(f"[Simulated] ZKP Proof: {zkp_proof}\n")

    # RSU verifies ZKP proof
    verification_result = rsu.verify_zkp(vehicle_id, zkp_proof, timestamp)
    if DEBUG_MODE:
        print(f"[Simulated] RSU Verification result: {verification_result}\n")

    # Simulate blockchain verification and logging
    outcome = simulate_blockchain_verification(vehicle_id, zkp_proof, timestamp, verification_result) if DEBUG_MODE else verification_result
    
    # Output infrastructure access result
    if outcome:
        passed += 1
        print("[Simulated] Access granted by infrastructure.\n")
    else:
        print("[Simulated] Access denied by infrastructure.\n")


"""End-to-end scenario: Vehicle authenticates successfully and is granted access, simulated"""
def scenario_successful_authentication():
    
    print("\n=== End-to-End Scenario: Successful Authentication ===")
    global tested, passed
    tested += 1
    
    # Generate entities
    vehicle_id = "VEH001"
    vehicle_secret = secrets.token_hex(16)
    vehicle = Vehicle(vehicle_id, vehicle_secret)
    rsu = RSU({vehicle_id: vehicle_secret})

    # Generate OTP and timestamp
    otp, timestamp = vehicle.generate_otp()
    if DEBUG_MODE:
        print(f"\nVehicle {vehicle_id} generated OTP: {otp} at {timestamp}\n")
        
    # Create ZKP proof
    zkp_proof = vehicle.create_zkp(otp, timestamp)
    if DEBUG_MODE:
        print(f"Vehicle {vehicle_id} created ZKP proof: {zkp_proof}\n")

    # RSU verifies ZKP proof
    verification_result = rsu.verify_zkp(vehicle_id, zkp_proof, timestamp)
    if DEBUG_MODE:
        print(f"RSU verification result: {verification_result}\n")

    # Blockchain verification and access outcome
    outcome = simulate_blockchain_verification(vehicle_id, zkp_proof, timestamp, verification_result) if DEBUG_MODE else verification_result
    if outcome:
        passed += 1
        print("Access granted by infrastructure.\n")
    else:
        print("Access denied by infrastructure.\n")


"""End-to-end scenario: Vehicle fails authentication due to wrong secret, simulated"""
def scenario_failed_authentication():
    
    print("\n=== End-to-End Scenario: Failed Authentication ===")
    global tested, passed
    tested += 1
    
    # Generate entities
    vehicle_id = "VEH001"
    correct_secret = secrets.token_hex(16)
    wrong_secret = secrets.token_hex(16)
    
    # Vehicle uses wrong secret
    vehicle = Vehicle(vehicle_id, wrong_secret)
    rsu = RSU({vehicle_id: correct_secret})

    # Generate OTP and timestamp
    otp, timestamp = vehicle.generate_otp()
    if DEBUG_MODE:
        print(f"\nVehicle {vehicle_id} generated OTP: {otp} at {timestamp}\n")
        
    # Create ZKP proof
    zkp_proof = vehicle.create_zkp(otp, timestamp)
    if DEBUG_MODE:
        print(f"Vehicle {vehicle_id} created ZKP proof: {zkp_proof}\n")

    # RSU verifies ZKP proof
    verification_result = rsu.verify_zkp(vehicle_id, zkp_proof, timestamp)
    if DEBUG_MODE:
        print(f"RSU verification result: {verification_result}\n")

    # Blockchain verification and access outcome
    outcome = simulate_blockchain_verification(vehicle_id, zkp_proof, timestamp, verification_result) if DEBUG_MODE else verification_result
    if outcome:
        print("Access granted by infrastructure (unexpected).\n")
    else:
        passed += 1
        print("Access denied by infrastructure (expected).\n")


"""Test the connection and workflow with ZoKrates CLI using dummy.zok"""
def test_zokrates_connection():
    
    print("\n=== ZoKrates CLI Connection Test ===")
    global tested, passed
    tested += 1
    circuit_path = os.path.join("..", "zokrates-files", "dummy.zok")
    
    # Compile circuit
    if not run_zokrates_compile(circuit_path):
        print("[ZoKrates Test] Compilation failed.")
        return
    
    # Setup
    if not run_zokrates_setup():
        print("[ZoKrates Test] Setup failed.")
        cleanup_zokrates_files()
        return
    
    # Compute witness (inputs: a=3, b=4)
    args = ["3", "4"]
    if not run_zokrates_compute_witness(args):
        print("[ZoKrates Test] Compute witness failed.")
        cleanup_zokrates_files()
        return
    
    # Generate proof
    if not run_zokrates_generate_proof():
        print("[ZoKrates Test] Proof generation failed.")
        cleanup_zokrates_files()
        return
    
    # Verify proof
    verification_result = run_zokrates_verify()
    if DEBUG_MODE:
        print(f"[ZoKrates Test] Verification result: {verification_result}\n")
    if verification_result:
        passed += 1
        print("[ZoKrates Test] ZoKrates connection and workflow succeeded!\n")
    else:
        print("[ZoKrates Test] ZoKrates connection or workflow failed.\n")
        
    # Clean up ZoKrates artifacts after test
    cleanup_zokrates_files()


"""Simulates a real ZKP workflow using the ZoKrates CLI on Linux"""
def test_vehicle_rsu_interaction_real_zokrates_dummy():
    
    print("\n=== Real ZoKrates End-to-End Test with dummy.zok ===")
    global tested, passed
    tested += 1
    circuit_path = os.path.join("..", "zokrates-files", "dummy.zok")
    
    # Generate random field inputs for dummy.zok
    a = random.randint(1, 100)
    b = random.randint(1, 100)
    if DEBUG_MODE:
        print(f"Inputs: a={a}, b={b}")
        
    # Compile circuit
    if not run_zokrates_compile(circuit_path):
        print("[Real ZKP] Compilation failed.")
        return
    
    # Setup
    if not run_zokrates_setup():
        print("[Real ZKP] Setup failed.")
        cleanup_zokrates_files()
        return
    
    # Compute witness
    args = [str(a), str(b)]
    if not run_zokrates_compute_witness(args):
        print("[Real ZKP] Compute witness failed.")
        cleanup_zokrates_files()
        return
    
    # Generate proof
    if not run_zokrates_generate_proof():
        print("[Real ZKP] Proof generation failed.")
        cleanup_zokrates_files()
        return
    
    # Verify proof
    verification_result = run_zokrates_verify()
    if DEBUG_MODE:
        print(f"[Real ZKP] Verification result: {verification_result}\n")
    if verification_result:
        passed += 1
        print("[Real ZKP] End-to-end ZoKrates workflow succeeded!\n")
    else:
        print("[Real ZKP] End-to-end ZoKrates workflow failed.\n")
        
    cleanup_zokrates_files()

"""ZKP isolated test with multiple vehicles, simulated"""
def test_simulated_isolated_multiple_vehicles():
    
    global tested, passed
    tested += 1
    print("\n=== Simulated ZKP Isolated Test: Multiple Vehicles ===")
    num_vehicles = 3
    vehicles = {}
    rsu_secrets = {}
    for i in range(num_vehicles):
        vid = f"VEH{i+1:03d}"
        secret = secrets.token_hex(16)
        vehicles[vid] = Vehicle(vid, secret)
        rsu_secrets[vid] = secret
    rsu = RSU(rsu_secrets)
    all_passed = True
    for vid, vehicle in vehicles.items():
        otp, timestamp = vehicle.generate_otp()
        zkp_proof = vehicle.create_zkp(otp, timestamp)
        result = rsu.verify_zkp(vid, zkp_proof, timestamp)
        if DEBUG_MODE:
            print(f"Vehicle {vid}: Verification result: {result}")
        all_passed = all_passed and result
    if all_passed:
        passed += 1
        print("[Simulated] All vehicles authenticated successfully.\n")
    else:
        print("[Simulated] Some vehicles failed authentication.\n")

"""End-to-end test with multiple vehicles, simulated"""
def test_simulated_end_to_end_multiple_vehicles():
    
    global tested, passed
    tested += 1
    print("\n=== Simulated End-to-End Test: Multiple Vehicles ===")
    num_vehicles = 3
    vehicles = {}
    rsu_secrets = {}
    
    # Generate multiple vehicles with unique IDs and secrets
    for i in range(num_vehicles):
        vid = f"VEH{i+1:03d}"
        secret = secrets.token_hex(16)
        vehicles[vid] = Vehicle(vid, secret)
        rsu_secrets[vid] = secret
    rsu = RSU(rsu_secrets)
    all_passed = True
    
    # Each vehicle generates OTP, creates ZKP, and RSU verifies
    for vid, vehicle in vehicles.items():
        otp, timestamp = vehicle.generate_otp()
        zkp_proof = vehicle.create_zkp(otp, timestamp)
        verification_result = rsu.verify_zkp(vid, zkp_proof, timestamp)
        outcome = simulate_blockchain_verification(vid, zkp_proof, timestamp, verification_result) if DEBUG_MODE else verification_result
        if DEBUG_MODE:
            print(f"Vehicle {vid}: RSU result: {verification_result}, Blockchain outcome: {outcome}")
        all_passed = all_passed and outcome
    if all_passed:
        passed += 1
        print("[Simulated] All vehicles granted access by infrastructure.\n")
    else:
        print("[Simulated] Some vehicles denied access.\n")

"""ZoKrates-integrated isolated test with multiple vehicles (dummy.zok)"""
def test_zokrates_isolated_multiple_vehicles():
    
    global tested, passed
    tested += 1
    print("\n=== ZoKrates-Integrated Isolated Test: Multiple Vehicles ===")
    circuit_path = os.path.join("..", "zokrates-files", "dummy.zok")
    num_vehicles = 2
    all_passed = True
    
    for i in range(num_vehicles):
        a = random.randint(1, 100)
        b = random.randint(1, 100)
        if DEBUG_MODE:
            print(f"Vehicle {i+1}: Inputs a={a}, b={b}")
        if not run_zokrates_compile(circuit_path):
            print("[ZoKrates] Compilation failed.")
            all_passed = False
            continue
        if not run_zokrates_setup():
            print("[ZoKrates] Setup failed.")
            cleanup_zokrates_files()
            all_passed = False
            continue
        args = [str(a), str(b)]
        if not run_zokrates_compute_witness(args):
            print("[ZoKrates] Compute witness failed.")
            cleanup_zokrates_files()
            all_passed = False
            continue
        if not run_zokrates_generate_proof():
            print("[ZoKrates] Proof generation failed.")
            cleanup_zokrates_files()
            all_passed = False
            continue
        verification_result = run_zokrates_verify()
        if DEBUG_MODE:
            print(f"Vehicle {i+1}: ZoKrates verification result: {verification_result}")
        if not verification_result:
            all_passed = False
            
        cleanup_zokrates_files()
        
    if all_passed:
        passed += 1
        print("[ZoKrates] All vehicles' proofs verified successfully.\n")
    else:
        print("[ZoKrates] Some vehicles' proofs failed verification.\n")

"""ZoKrates-integrated end-to-end test with multiple vehicles (dummy.zok + simulated blockchain)"""
def test_zokrates_end_to_end_multiple_vehicles():
    
    global tested, passed
    tested += 1
    print("\n=== ZoKrates-Integrated End-to-End Test: Multiple Vehicles ===")
    circuit_path = os.path.join("..", "zokrates-files", "dummy.zok")
    num_vehicles = 2
    all_passed = True
    
    # Generate multiple vehicles with unique IDs and random inputs
    for i in range(num_vehicles):
        vid = f"ZOKR_VEH{i+1:03d}"
        a = random.randint(1, 100)
        b = random.randint(1, 100)
        if DEBUG_MODE:
            print(f"Vehicle {vid}: Inputs a={a}, b={b}")
        if not run_zokrates_compile(circuit_path):
            print("[ZoKrates] Compilation failed.")
            all_passed = False
            continue
        if not run_zokrates_setup():
            print("[ZoKrates] Setup failed.")
            cleanup_zokrates_files()
            all_passed = False
            continue
        args = [str(a), str(b)]
        if not run_zokrates_compute_witness(args):
            print("[ZoKrates] Compute witness failed.")
            cleanup_zokrates_files()
            all_passed = False
            continue
        if not run_zokrates_generate_proof():
            print("[ZoKrates] Proof generation failed.")
            cleanup_zokrates_files()
            all_passed = False
            continue
        verification_result = run_zokrates_verify()
        if DEBUG_MODE:
            print(f"Vehicle {vid}: ZoKrates verification result: {verification_result}")
        outcome = simulate_blockchain_verification(vid, f"proof_{a}_{b}", int(time.time()), verification_result) if DEBUG_MODE else verification_result
        if DEBUG_MODE:
            print(f"Vehicle {vid}: Blockchain outcome: {outcome}")
        if not (verification_result and outcome):
            all_passed = False
            
        cleanup_zokrates_files()
        
    if all_passed:
        passed += 1
        print("[ZoKrates] All vehicles' end-to-end proofs and blockchain logs succeeded.\n")
    else:
        print("[ZoKrates] Some vehicles failed end-to-end ZoKrates or blockchain verification.\n")


"""Run all test and scenario functions and print summary statistics"""
def testAndScenarioRunner():

    test_simulated_isolated_multiple_vehicles()
    time.sleep(1)
    # clear_console()

    test_simulated_end_to_end_multiple_vehicles()
    time.sleep(1)
    # clear_console()

    test_zokrates_isolated_multiple_vehicles()
    time.sleep(1)
    # clear_console()

    test_zokrates_end_to_end_multiple_vehicles()
    time.sleep(1)
    # clear_console()

    test_zokrates_connection()
    time.sleep(1)
    # clear_console()

    test_vehicle_rsu_interaction_real_zokrates_dummy()
    time.sleep(1)
    # clear_console()

    test_vehicle_rsu_interaction_simulated()
    time.sleep(1)
    # clear_console()

    test_vehicle_rsu_blockchain_simulated()
    time.sleep(1)
    # clear_console()

    scenario_successful_authentication()
    time.sleep(1)
    # clear_console()

    scenario_failed_authentication()
    time.sleep(1)
    # clear_console()
    
    print(f"\nTotal tests run: {tested}")
    print(f"Total tests passed: {passed}")
    print(f"Total tests failed: {tested - passed}")
    print()
    time.sleep(3)

if __name__ == "__main__":
    testAndScenarioRunner()