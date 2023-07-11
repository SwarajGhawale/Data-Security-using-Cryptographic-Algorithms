
def RC4(P, key, size):
    S = []
    T = []
    for i in range(size):
        S.append(i)
        T.append(key[i % len(key)])
    report = "Step 1: Generate the stream" + "\n"   
    report += "S: " + str(S) + "\n" + "T:" + str(T) + "\n\n"
    
    def swap(S, i, j):
        temp = S[i]
        S[i] = S[j]
        S[j] = temp
        return S
        
    report += "__"*20 + "\n" 
    report += "Step 2: Initial permutation"+ "\n" 
    
    # initial permutation
    j = 0
    for i in range(size):
        j = (j + S[i] + T[i]) % size
        S = swap(S, i, j)
        report += f"i = {i},   j = {j}     S = {S}" + "\n"
    
    report += "__"*20 + "\n"
    i = j = 0
    k = 0
    cnt = 0
    sec = True
    random = []
    while(True):
        i = (i+1) % size 
        j = (j + S[i]) % size

        report += "i: " + str(i) + "\n" + "j: " + str(j) + "\n"
        S = swap(S, i, j)
        
        t = (S[i] + S[j]) % size
        report += "t: " + str(t) + "\n" + "S: " + str(S) + "\n"
        
        k = S[t]
        report += "k: " + str(k) + "\n\n"
        
        if len(P) == len(random):
            break
        random.append(k)
    
    result = []    
    for i in range(len(P)):
        binary_random = bin(random[i])[2:].zfill(3)  # convert to binary, slice off the "0b" prefix and fill with zeros to become 3 digits
        binary_P = bin(P[i])[2:].zfill(3)
        xor = bin(int(binary_random, 2) ^ int(binary_P, 2))[2:].zfill(3)  # convert binary strings back to int, perform XOR, convert result back to binary and fill with zeros to become 3 digits
        result.append(xor)
    report += str(result)
    return result, report



