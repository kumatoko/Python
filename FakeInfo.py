# I found this a while back and thought it could be a useful script. 
# Super simple, but handy if you need to fill out a database. 

from faker import Faker

faker = Faker()

print (f"name: {faker.name()}")
print (f"address: {faker.address()}")

print (f"text: {faker.text()}")

