# Original source code from "Mastering Bitcoin" by Andreas M. Antonopoulos

import hashlib
import time

try: # Python 2
	long
	xrange
except: # Python 3 
	long = int
	xrange = range


maxNonce = 2 ** 32 # 4 billion

def proofOfWork(header, difficultyBits):
	target = 2 ** (256 - difficultyBits);
	
	for nonce in xrange(maxNonce):
		hashResult = hashlib.sha256((str(header) + str(nonce)).encode('utf-8')).hexdigest();
		
		if long(hashResult, 16) < target:
			print("Success with nonce %d" % nonce);
			print("Hash is %s" % hashResult);
			return(hashResult, nonce);
		
	print("Failed after %d (maxNonce) tries" % nonce);
	return nonce;


if __name__ == '__main__':
	nonce = 0;
	hashResult = '';
	
	for difficultyBits in xrange(32):
		difficulty = 2 ** difficultyBits;
		print("Difficulty: %ld (%d bits)" % (difficulty, difficultyBits));
		print("Starting search...");
		
		startTime = time.time()
		
		# we fake a block of transactions -> just a string
		newBlock = 'test block with transactions' + hashResult;
		
		# find a valid nonce for the new block
		(hashResult , nonce) = proofOfWork(newBlock, difficultyBits);
		
		endTime = time.time();
		
		elapsedTime = endTime - startTime;
		print("Elapsed Time: %.4f seconds" % elapsedTime);
		
		if elapsedTime > 0:
			hashPower = float(long(nonce) / elapsedTime);
			print("Hashing Power: %ld hashes per second" % hashPower);



		
		
    
