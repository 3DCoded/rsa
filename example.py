from rsa import *

print()

print('Code: ')

print()

print('pub, pri = genkey(2**16)')
pub, pri = genkey(2**16)

print('key = genvigkey(100)')
key = genvigkey(100)

print('vigencoded = vigencode("message", key)')
vigencoded = vigencode("message", key)

print('vigdecoded = vigdecode(vigencoded, key)')
vigdecoded = vigdecode(vigencoded, key)

print('rsaencoded = encode("message", pub)')
rsaencoded = encode("message", pub)

print('rsadecoded = decode(rsaencoded, pri)')
rsadecoded = decode(rsaencoded, pri)

print('hackedpri = genprikey(pub)')
hackedpri = genprikey(pub)

print()

print('Globals: ')

print()

for name in 'pub pri key vigencoded vigdecoded rsaencoded rsadecoded hackedpri'.split():
    print(f'{name} = {globals()[name]}')

print('NOTE that the genprikey function only works on small public keys. ')
