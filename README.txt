# CS 6238 Project 1
# Andrew Wilder
# Prabhendu Pandey
---------------------


Source Code 
------------
SecLogin.java 


Compilation
------------
Use "make" in the directory with the Makefile


Usage
------
java SecLogin "testfile.txt"


Basic Assumptions in program:
---------------------------------
-- Number of features supported is 15.
-- Threshold value for features is 500 ms. It means that the approx mean of the features lies around threshold. 
-- Value of constant k is 0.1 .
-- Entries maintained in history file is 20.
-- Users will be prompted to input password. The password field will accept only 8 characters.
Less than 8 character passwords will be padded with the last remaining characters of "password".
Characters going beyond 8 will be truncated.
-- Value of q is generated randomly only once and is mentioned in the program.
-- History file is encrypted using hardened password.
-- Instruction table is stored (not encrypted as it is calculated using hash values).
-- Initially 9 logins are used to build up the mean and average. For logins after that, recalculation of hardened password is done using appropriate values (alpha or beta based on conditions).
-- Testfile format:
	seqnum username feat1 feat2 ... feat15
	seqnum username feat1 ...