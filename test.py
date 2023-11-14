from PKE import RSA

key = RSA.Generate(1024)

with open("private.pem", "w") as f:
    f.write(key.Export())
    f.close()

with open("public.pem", "w") as f:
    f.write(key.public.Export())
    f.close()