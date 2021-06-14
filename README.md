## Auth_Process
#### Description:- Authentication module 
### Features
- User Sign Up 
- User authentication
- Token based authorization
- Role based access
- Email verification
- Forgot password
- CRUD operations
- Logout
### Functionalities
- authenticates users by their username and mapping password hash 
- create and verify access and refresh tokens in every required operations
- custom decorator to maintain access limitations to the users
- custom password generator
- custom password validation
- pasword hashing
- validate and verify users email 
- CRUD operations possible in tables using ORM
- logout users revoking tokens

authenticates users, role based authorization to the users. It has the features like  email verification, token based authorization, refresh token, password generator, password and email validation and logout process.Moreover, it does the CRUD operation using ORM .



### To SetUp and Start
```python
pip install -r requirement.txt
python run.py
```

- Database
  - table as your requirement




  
  

