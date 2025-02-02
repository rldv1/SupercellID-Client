# SupercellID-Client

Since the latest versions of the game, Supercell has added protection against fake requests to their API called Request Forgery Protection (RFP).

> I dont want to see people who are crazy about money get the logic of this protection through disassemblers and sell it for a lot of money.
> 
> I sincerely hope that Supercell will notice this repository and take some actions

## What do I highly recommend to Supercell to secure their API?
- Dont use signing functions in libg, its absurd and unsafe
- Instead use obfuscated Dart code, and given that Dart runs in a VM, this will make it extremely difficult to analyze behavior
- Use custom hashing algorithms, the current implementation of HMAC-SHA256 looks sad
- Use PepperCrypto :)

## How does RFP work?
#### Example input data:
`1738503470GET/api/rewards/sdk/v1/rewards.statusauthorization=Bearer <exampleToken>user-agent=scid/1.5.8-f (iPadOS 18.2; laser-prod; iPad8,6) com.supercell.laser.K3X97T336N/59.184x-supercell-device-id=5A8F68A1-A0D8-5702-95A8-875CF3F421F8`
#### Example finished signature:
`RFPv1 Timestamp=1738503470,SignedHeaders=authorization;user-agent;x-supercell-device-id,Signature=nCahKjUPwvOcGQW5tLt7cLZb3Ol6yU3Q_KVFjx7Z5Vc`
#### Before signing, the following information is collected:
- Datetime (Seconds since Epoch)
- Body
- Method (POST, GET, etc.)
- API Path
- Some headers (User-agent, authorization (bearer), etc.)
### Next, go to the `sub_BA8004` (signer) function!
Remember what I said? This is not secure, such sensitive code cannot be 100% protected JUST by Promon... :/

#### Let's imagine that you have a Supercell ID menu like this:
<img width="364" alt="Снимок экрана 2025-02-02 в 22 09 18" src="https://github.com/user-attachments/assets/355c9e76-b6e6-46c7-8883-24603d21ab2b" />

#### Once you press the "LOG IN" button, a series of Dart calls follow, and eventually we follow this chain:
1. ↓ [scid_flutter/src/id_services.dart] IdServices::_sign  ↓
2. ↓ [scid_flutter/src/communication/scid_message_channel.dart] ScidMessageChannel::sign ↓
3. --> [flutter/src/services/platform_channel.dart] MethodChannel::invokeMethod <--

### MethodChannel::invokeMethod? What is this?
In Dart (on Android) `MethodChannel::invokeMethod` is used to call native (Java/C++) code from a Flutter app. This is part of the Platform Channel mechanism (Method Channel), which allows Flutter to interact with native Android code.

**In our case, the function is taken by libscid_sdk.so**, this is where our "receiver" of these calls is located
<p align="center">
<img width="683" alt="Снимок экрана 2025-02-02 в 22 19 35" src="https://github.com/user-attachments/assets/8f1a840b-68d8-4578-bf73-50336b5592f0" />
<br>
<em>Yep! There is! This is the handler for our "sign" message</em>
</p>
We see that next comes a jump into something

```c
(*(void (__fastcall **)(void ***__return_ptr, _QWORD, unsigned __int64, unsigned __int64, void *, void **, unsigned __int64))(**(_QWORD **)(this + 8) + 336LL))(
      &v419,
      *(_QWORD *)(this + 8),
      (unsigned __int64)v412 & 0xFFFFFFFFFFFFFFFELL,
      v413 & 0xFFFFFFFFFFFFFFFELL,
      v414,
      &p_dest,
      *((_QWORD *)&v413 + 1) & 0xFFFFFFFFFFFFFFFELL);
```
A simple VTable function, which surprisingly leads to `libg.so` at `sub_BA8004`!


##### Below is my deobfuscated version of this function (i worked on it for about 30 minutes!)
```cpp
// The function generates a packet signature using:
// – a string representation of the timestamp (the primary parameter),
// – header data (parameters a2),
// – the request body (parameters a1),
// – and some key (parameters a5), using an additional structure (a4)
// to get additional data.
// The resulting signature is written to the buffer specified in a6.
// Note that the function returns a long double value – this can be the result of a
// calculation (e.g., a hash), which is then copied to the output buffer.
  long double generateSignature(
    unsigned char* reqData, // a1 – request data (or request header)
    int64_t headerStruct, // a2 – pointer to packet header structure
    std::string requestBody, // a3 – request body (passed as string)
    int64_t keyStruct, // a4 – structure used for additional calculations
    unsigned char* keyData, // a5 – key data
    int64_t outSignatureBuf // a6 – pointer to resulting structure (buffer) for signature
)
{
    //
    // 1. Convert timestamp to string.
    // In the original, std::to_string is called, the result is not explicitly saved,
    // but is then used to form the final signature.
    //
    std::string timestampStr = std::to_string(reinterpret_cast<int64_t>(reqData));
    
    //
    // 2. Processing packet header data from the headerStruct structure.
    // The first byte stores a flag that determines how the data is interpreted:
    // – if the least significant bit is 0, the data is “inline”: immediately after the flag is a string of length (flag >> 1)
    // – otherwise, the data is located at the address stored in the structure field.
    //
    uint8_t headerFlag = *(reinterpret_cast<uint8_t*>(headerStruct));
    bool headerIsInline = ((headerFlag & 1) == 0);
    uint64_t headerDataLen = headerFlag >> 1;
    const char* headerData = nullptr;
    if ( headerIsInline )
        headerData = reinterpret_cast<const char*>(headerStruct + 1);
    else
        headerData = *reinterpret_cast<const char**>(headerStruct + 16);
    
    // If the data is "inline" - the length is taken from the flag, otherwise from the structure field.
    uint64_t headerStrLen = headerIsInline ? headerDataLen : *reinterpret_cast<uint64_t*>(headerStruct + 8);
    
    std::string headerStr;
    headerStr.append(headerData, headerStrLen);
    // After calling string::append the original "clears" the temporary buffers - here we just move on.
    
    
    //
    // 3. Processing the request body from reqData (similar algorithm as for the header).
    //
    uint8_t reqFlag = *reqData;
    bool reqIsInline = ((reqFlag & 1) == 0);
    uint64_t reqDataLen = reqFlag >> 1;
    const char* reqContent = nullptr;
    if ( reqIsInline )
        reqContent = reinterpret_cast<const char*>(reqData + 1);
    else
        reqContent = *reinterpret_cast<const char**>(reqData + 16);
    
    uint64_t reqStrLen = reqIsInline ? reqDataLen : *reinterpret_cast<uint64_t*>(reqData + 8);
    
    std::string reqStr;
    reqStr.append(reqContent, reqStrLen);
    // "Clearing" the temporary reqStr buffer should occurs automatically.
    
    
    //
    // 4. Processing key data from keyData (AGAIN the similar logic).
    //
    uint8_t keyFlag = *keyData;
    bool keyIsInline = ((keyFlag & 1) == 0);
    uint64_t keyDataLen = keyFlag >> 1;
    const char* keyContent = nullptr;
    if ( keyIsInline )
        keyContent = reinterpret_cast<const char*>(keyData + 1);
    else
        keyContent = *reinterpret_cast<const char**>(keyData + 16);
    
    uint64_t keyStrLen = keyIsInline ? keyDataLen : *reinterpret_cast<uint64_t*>(keyData + 8);
    
    std::string keyStr;
    keyStr.append(keyContent, keyStrLen);
    // The temporary keyStr is "cleared" next.
    
    
    //
    // 5. Preparing additional constant strings for signature generation.
    // String literals are used here, for example: "Authorization" and "X-Supercell-Device-Id" and other one (i can't remember it, sadly :c).
    //
    const char* authKey = "Authorization";
    const char* deviceKey = "X-Supercell-Device-Id";
    
    // Initialize buffers (simulate creation of string objects with dynamically allocated memory)
    std::string authStr(authKey);
    std::string deviceStr(deviceKey);
    
    
    //
    // 6. Processing the authKey string with possible memory allocation by size.
    // if the string length exceeds the threshold (>= 23 characters), an aligned block is allocated,
    // otherwise, copying is performed via a pointer to an internal buffer.
    //
    size_t authLen = strlen(authKey);
    std::string processedAuth;
    if ( authLen >= 0x17 /* 23 */ ) {
        // Select a block with alignment (analog of the expression (authLen+16)&~0xF)
        processedAuth.resize( (authLen + 16) & ~static_cast<size_t>(0xF) );
        memcpy(&processedAuth[0], authKey, authLen);
    }
    else {
        // If the string is small, just copy it
        processedAuth = authKey;
    }
    processedAuth.push_back('\0'); // UTF-8 end.
    
    
    //
    // 7. Calling sub_BB0DD8, probably to process the header line.
    //    The result is compared with (a4 + 8) - if it does not match, we go to the loop for processing the set of rows.
    //
    int64_t processedHeaderPtr = sub_BB0DD8(keyStruct, reinterpret_cast<unsigned char*>(&headerStr));
    if ( (keyStruct + 8) != processedHeaderPtr )
    {
        // v31 – pointer to an array of strings (for example, header names);
        // here represented as an array of pointers to char.
        const char** headerArray = /* pointer to an array of strings obtained earlier (v169) */;
        
        // Process each element of the headerArray array in a loop
        // (the exact number of elements is determined based on the data, here we will denote it as headerCount, but usually there should be 3)
        size_t headerCount = 0x3;
        for (size_t i = 0; i < headerCount; i++) {
            const char* curHeader = headerArray[i];
            size_t curLen = strlen(curHeader);
            std::string curHeaderStr;
            if ( curLen >= 0x17 ) {
                curHeaderStr.resize( (curLen + 16) & ~static_cast<size_t>(0xF) );
                memcpy(&curHeaderStr[0], curHeader, curLen);
            } else {
                curHeaderStr = curHeader;
            }
            curHeaderStr.push_back('\0');
            
            // Apply character conversion - convert capital letters to lowercase.
            // (In the src, this part is implemented using NEON instructions)
            for (char &ch : curHeaderStr) {
                if ( ch >= 'A' && ch <= 'Z' )
                    ch |= 0x20;
            }
            
            // Add the processed string to the shared buffer (analogous to sub_3BC7EC)
            // For example:
            // intermediateBuffer.append(curHeaderStr);
            
            // Reset temp variables for the current element (analogous to operator::delete for a temporary buffer)
            
            // Next, add the "=" symbol to the end of the processed string:
            // intermediateBuffer.append("=", 1);
            
            // And call another loc_BAB868 to get an additional block
            int64_t locResult = loc_BAB868(keyStruct, /* v163 */, &curHeaderStr);
            if (!locResult)
                abort(); // if the result is zero - crash
            
            // From the structure returned by locResult, extracting:
            uint8_t locFlag = *(reinterpret_cast<uint8_t*>(locResult + 56));
            bool locInline = ((locFlag & 1) == 0);
            uint64_t locLen = locFlag >> 1;
            const char* locData = locInline ? reinterpret_cast<const char*>(locResult + 57)
                                            : *reinterpret_cast<const char**>(locResult + 72);
            uint64_t locDataLen = locInline ? locLen : *reinterpret_cast<uint64_t*>(locResult + 64);
            
            // Append the received data to the general buffer (maybe  intermediateBuffer.append(locData, locDataLen);)
            
        }
    }
    
    
    //
    // 8. Next, a strange cycle occurs, in which from a set of blocks (from the memory area from v177 to v178)
    // a string is sequentially formed, between blocks (if there are several of them) 
    // an additional line is added (from v169/v170). The original calculates the number of blocks 
    // using multiplication by the constant 0xAAAAAAAAAAAAAAABLL.
    //
    std::string combinedBuffer;
    {
        // The number of blocks is defined as:
        size_t blockCount = /* (v178 - v177) / 8 */;
        for (size_t blockIndex = 0; blockIndex < blockCount; blockIndex++) {
            // Retrieve a 24-byte block from the memory area (v177 + blockIndex*24)
            // and add it to combinedBuffer:
            // combinedBuffer.append(v177_block, 24);
            
            // If this is not the last block, add an intermediate separator,
            // which is taken from v169/v170 (see source for details)
            if ( blockIndex < blockCount - 1 ) {
                // combinedBuffer.append(разделитель);
            }
        }
        // If necessary, free the mem allocated for v169 (if the flag shows that memory was allocated, and it should be there AS AS MUCH AS I REMEMBER)
    }
    
    
    //
    // 9. We reset the previous lines and write in them the 32-byte key used for hashing
    //
    // Here:
    //   v169 = 0;
    //   v170 = 0;
    //   v167 = xmmword_1B4FB8;
    //   v168 = unk_1B4FC8;
    //
    // And finally:
    sub_BA8D68(reinterpret_cast<int64_t>(&v167), &v165);
    
    
    //
    // 10. The most important part of our DJ shitcore party! Hash calculation based on the key.
    // Called sub_BB1B34, which receives:
    // – pointer to v165,
    // – length (0x20),
    // – key data (from keyStr),
    // – pointer to v169,
    // – and one more parameter 0x20.
    //
    int hashInput = sub_BB1B34(&v165, 0x20, reinterpret_cast<const unsigned char*>(keyStr.data()), keyStr.size(), &v169, 0x20);
    
    // Next, sub_D2FED8 is called, the result of return is (4 * ((len + 2) / 3)) | 1;
    int hashTotalLen = sub_D2FED8(hashInput);
    int finalHashLen = hashTotalLen - 1;
    
    // aLLlLLlOooOOOCCCccAaaAttiiIiiNgggG AGGGAAIN a buffer for the final hash.
    std::string finalHash;
    if ( finalHashLen >= 0x17 ) {
        // Selecting block with alignment:
        size_t allocSize = (hashTotalLen + 15) & ~static_cast<size_t>(0xF);
        finalHash.resize(allocSize);
    }
    else {
        finalHash.resize(finalHashLen);
    }
    memset(&finalHash[0], 0, finalHashLen);
    finalHash[finalHashLen] = '\0';
    
    // Depending on the flag (memory allocation inline or through a pointer), we get a pointer to the data:
    char* finalHashData = &finalHash[0];  // (if the flag is inline) otherwise - otherwise
    // Fill the resulting hash buffer:
    sub_D2FF04(finalHashData, reinterpret_cast<int64_t>(&v169), hashInput);
    
    
    //
    // 11. This is also an important part!! Post-processing of the final hash string:
    // – Replacing the '+' symbol with '-' (implemented using vector (NEON) operations,
    // if the buffer length allows, otherwise - loop through the bytes).
    // – Similar processing of the symbol '/' → '_'.
    // – Remove '=' characters (if they appear at the end).
    //
    size_t hashSize = finalHash.size();
    if ( hashSize >= 8 ) {
        // Processing in blocks of 8 bytes (in the original - with NEON instructions).
        for (size_t i = 0; i < hashSize; i += 8) {
            for (size_t j = i; j < std::min(hashSize, i + 8); j++) {
                if ( finalHash[j] == '+' )
                    finalHash[j] = '-';
            }
        }
    }
    else {
        // Each byte!
        for (size_t i = 0; i < hashSize; i++) {
            if ( finalHash[i] == '+' )
                finalHash[i] = '-';
        }
    }
    
    // '/' to '_'
    for (size_t i = 0; i < hashSize; i++) {
        if ( finalHash[i] == '/' )
            finalHash[i] = '_';
    }
    
    // Remove '=' characters. If '=' is encountered, all subsequent characters are excluded.
    size_t eqPos = finalHash.find('=');
    if ( eqPos != std::string::npos && eqPos + 1 < finalHash.size() ) {
        std::string tmp;
        for (size_t i = eqPos; i < finalHash.size(); i++) {
            if ( finalHash[i] != '=' )
                tmp.push_back(finalHash[i]);
        }
        finalHash = tmp;
    }
    
    
    //
    // 12. Formation of the final signature.
    // A final string is created consisting of:
    // – Prefix "RFPv1 Timestamp=" with the addition of timestampStr,
    // – Then, through calls to std::to_string and std::insert, add
    // other components (for example, intermediate buffers obtained in steps 7–8),
    // – And finally, the final hash (finalHash).
    //
    std::string finalSignature;
    finalSignature.append("RFPv1 Timestamp=");
    finalSignature.append(timestampStr);
    
    // Example of inserting an intermediate buffer (for example, obtained from authStr and processed earlier)
    std::string authInserted = std::string("RFPv1 Timestamp=") + timestampStr;
    // Next we add the result of std::string::append() from v159/v161, etc.
    // (the exact sequence of operations in the original is quite heavily obfuscated - below is a pseudoexample)
    authInserted.append(" ");
    authInserted.append(/* some line from the intermediate buffer formed in steps 7–8 */);
    authInserted.append(" ");
    authInserted.append(finalHash);
    
    // The result is written to the output buffer (i think that outSignatureBuf is a std::string structure)
    *reinterpret_cast<std::string*>(outSignatureBuf) = authInserted;
    
    
    
    
    //
    // 13. Return the final value.
    // In the original, a long double is returned, which is read from the resulting buffer.
    // Here we simulate this conversion.
    //
    long double result;
    memcpy(&result, finalSignature.data(), sizeof(result));
    
    return result;
}
```


## RFP Keys:
- Laser v59: `ae584daf58a3757be21fb506dfcfc478fad4600e688d5bb6f3e51ccb2ebfc373`
