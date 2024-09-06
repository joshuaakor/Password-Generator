import customtkinter
import sqlite3
import secrets
import bcrypt
import tkinter as Tk
from CTkMessagebox import CTkMessagebox
from tkinter import ttk
from customtkinter import CTkToplevel

database = sqlite3.connect('database.db')

cursor = database.cursor()

cursor.execute('''CREATE TABLE IF NOT EXISTS usersss( 
              username TEXT NOT NULL,
              password TEXT NOT NULL)''')

cursor.execute('''CREATE TABLE IF NOT EXISTS generated_passwords (
                id INTEGER PRIMARY KEY,
                password_name TEXT NOT NULL,
                password_text TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id))''')

#cursor.execute('''ALTER TABLE generated_passwords 
 #                 ADD COLUMN user_id INTEGER''')


customtkinter.set_appearance_mode("dark")
customtkinter.set_default_color_theme("dark-blue")

root = customtkinter.CTk()
root.geometry("{0}x{1}+0+0".format(root.winfo_screenwidth(), root.winfo_screenheight()))

font1 = ('Arial', 13, 'bold', 'underline')



def signup_window():
    global window_open, register_window
    if not window_open:
        register_window = customtkinter.CTkToplevel(root)
        register_window.title("Sign Up")
        register_window.geometry("500x350")
        register_window.protocol("WM_DELETE_WINDOW", on_close)
        register_window.grab_set()
        window_open = True
        noaccount_button.configure(state=customtkinter.DISABLED)
   


    signup_label = customtkinter.CTkLabel(master=register_window, text="Sign up")
    signup_label.pack(pady=12, padx=10)

    global username_entry
    username_entry = customtkinter.CTkEntry(master=register_window, placeholder_text="Username")
    username_entry.pack(pady=12, padx=10)

    global password_entry
    password_entry = customtkinter.CTkEntry(master=register_window, placeholder_text="Password", show="*")
    password_entry.pack(pady=12, padx=10)

    global retype_password
    retype_password = customtkinter.CTkEntry(master=register_window, placeholder_text="Retype password", show="*")
    retype_password.pack(pady=12, padx=10)

    signup_button = customtkinter.CTkButton(master=register_window, text="Sign Up", command=signup)
    signup_button.pack(pady=12, padx=10)

    
    #Signup Function

def signup():
    username = username_entry.get()
    password = password_entry.get()
    password2 = retype_password.get()

        
        
    if username != '' and password != '' and password2 != '':
        if password != password2:
            pass
            CTkMessagebox(title="Alert", message="Passwords do not match")
        else:
            cursor.execute('SELECT username FROM usersss WHERE username=?', [username])
            
            if cursor.fetchone() is not None:
                CTkMessagebox(title="Alert", message="Username already exists")
            
            else:
                encoded_password = password.encode('utf-8')
                hashed_passwords = bcrypt.hashpw(encoded_password, bcrypt.gensalt())
                cursor.execute('INSERT INTO usersss VALUES (?, ?)', [username, hashed_passwords])
                database.commit()
                CTkMessagebox(title="Alert", message="Account created successfully!")
                on_close()
                
            
        
    else:
        CTkMessagebox(title="Alert", message="Enter all Data")




def login_success(show_message=True):

    
    if show_message:
        CTkMessagebox(title="Alert", message="Login Successful!")
    
    login_frame = customtkinter.CTkFrame(master=root)
    login_frame.pack(pady=70, padx=60, fill="both", expand=True)

    login_label = customtkinter.CTkLabel(master=login_frame, text="Options", font=("Times New Roman",22), text_color="red")
    login_label.pack(pady=12, padx=10)

    def sign_out():
        login_frame.pack_forget()
        CTkMessagebox(title="Alert", message="You have signed out")

        default_page()

    
# View passwords after they have been saved
    
    def view_saved_passwords():
   



        cursor.execute('SELECT * FROM usersss WHERE username=?', [valid_username])
        userss2 = cursor.fetchone()

        if userss2:
            for users in userss2:
                users_id = users[0]

        cursor.execute('SELECT * FROM generated_passwords WHERE user_id=?', (users_id,))
        view_passwords = cursor.fetchall()

        passwords_window = Tk.Tk()
        passwords_window.title("Saved Passwords")
        
        
# Define columns 
        tree = ttk.Treeview(passwords_window, columns=("password_name", "password_text")) 

# Assign width and minimum width

        tree.column("password_name", width=150, minwidth=150, anchor=Tk.CENTER)
        tree.column("password_text", width=150, minwidth=150, anchor=Tk.CENTER)

# Assign Heading names to respective column
        tree.heading("#0", text="ID", anchor=Tk.CENTER)
        tree.heading("password_name", text="Password Name", anchor=Tk.CENTER)
        tree.heading("password_text", text="Password Text", anchor=Tk.CENTER)

        for v_passwords in view_passwords:
            tree.insert("", "end", text=v_passwords[0], values=(v_passwords[1], v_passwords[2]))

        tree.pack(expand=True, fill="both")
    
    
    def create_pass():
        login_frame.pack_forget()
        
        crtpass_frame = customtkinter.CTkFrame(master=root)
        crtpass_frame.pack(pady=20, padx=60, fill="both", expand=True)

        label = customtkinter.CTkLabel(master=crtpass_frame, text="Create Password")
        label.pack(pady=12, padx=10)

        global password_name
        password_name = customtkinter.CTkEntry(master=crtpass_frame, placeholder_text="Enter Password Name", width=250)
        password_name.pack(pady=12, padx=10)

        global password_name_value
        password_name_value = password_name.get()


        def save_generated_password():
            try:
                cursor.execute('SELECT * FROM usersss WHERE username=?', [valid_username])
                userss = cursor.fetchone()
                print(userss)

                if userss:
                    for user in userss:
                        user_id = user[0]
                        cursor.execute('INSERT INTO generated_passwords (user_id, password_name, password_text) VALUES (?, ?, ?)', (user_id, password_name_value, generated_pass))
                        database.commit()
                    CTkMessagebox(title="Alert", message="Password Saved!")
                    save_password.configure(state=customtkinter.DISABLED)
                else:
                    CTkMessagebox(title="Alert", message="Error. User Not Found")
            except Exception as e:
                print(str(e))

        
        
        char_num = customtkinter.CTkEntry(master=crtpass_frame, placeholder_text="Enter number of password characters", width=250)
        char_num.pack(pady=12, padx=10)


        def password_generate():
            if password_name.get() == "" and char_num.get() == "":
                CTkMessagebox(title="Alert", message="Feilds cannot be empty")
            elif char_num.get() == "" and password_name.get().strip():

                CTkMessagebox(title="Alert", message="Type in number of password characters")
            elif password_name.get() == "" and char_num.get().strip():
                CTkMessagebox(title="Alert", message="Passwords must have names")
            else:
                try:
                    int(char_num.get())
                except:
                    CTkMessagebox(title="Alert", message="Input must be digit")

            capital_letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            small_letters = "abcdefghijklmnopqrstuvwxyz"
            number_list = "0123456789"
            special_char = "!£$%^&*()_-+=#~[]{'}@:;/?.><,|`"""

            password_length = int(char_num.get())
            characters = capital_letters + small_letters + number_list + special_char
            global generated_pass
            generated_pass = ''.join(secrets.choice(characters) for _ in range(password_length))
            
            ## password will not be generated if password name is empty ##
            def dont_generate():
                if password_name.get() == "":
                    pass
                else:
                    password_label.configure(text="Generated Password: " + generated_pass, font=("Times New Roman", 22))
            dont_generate()
            save_password.configure(state=customtkinter.NORMAL)

        
        generate_pass = customtkinter.CTkButton(master=crtpass_frame, text="Generate Password", command=password_generate)
        generate_pass.pack(pady=12, padx=10)
            
        password_label = customtkinter.CTkLabel(master=crtpass_frame, text="")
        password_label.pack(pady=12, padx=10)

        global save_password
        save_password = customtkinter.CTkButton(master=crtpass_frame, text="Save Password", command=save_generated_password)
        save_password.pack(pady=12, padx=10)
        save_password.configure(state=customtkinter.DISABLED)



##  Function for the back button 
        def back_function():
            crtpass_frame.pack_forget()

            login_success(show_message=False)




        back_button = customtkinter.CTkButton(master=crtpass_frame, text="\u2190 Back", width=50, command=back_function)
        back_button.place(x=50, y=20)

    #def back_function2():
        #   view_pass_frame.pack_forget()
        
    
    
    signout_button = customtkinter.CTkButton(master=login_frame, text="Sign Out", command=sign_out, width=50)
    signout_button.place(x=1050, y=20,)

    create_password = customtkinter.CTkButton(master=login_frame, text="Create New Password", width=200, command=create_pass)
    create_password.place(x=480, y=150)

    saved_passwords = customtkinter.CTkButton(master=login_frame, text="View Saved Passwords", width=200, command=view_saved_passwords)
    saved_passwords.place(x=480, y=200)




#def login_fail():
 #   CTkMessagebox(title="Alert", message="Login Failed\n Username or Password incorrect")

def default_page():

    frame = customtkinter.CTkFrame(master=root)
    frame.pack(pady=20, padx=60, fill="both", expand=True)

    label = customtkinter.CTkLabel(master=frame, text="Login System")
    label.pack(pady=12, padx=10)


    global username5
    username5 = customtkinter.CTkEntry(master=frame, placeholder_text="Username")
    username5.pack(pady=12, padx=10)

    global password5
    password5 = customtkinter.CTkEntry(master=frame, placeholder_text="\U0001F511 Password", show="*")
    password5.pack(pady=12, padx=10)



   ## Login Authentication ## 
    def authentication():
        
        global valid_username
        global valid_password
        valid_username = username5.get()
        valid_password = password5.get()

        if valid_username != '' and valid_password != '':
            cursor.execute('SELECT password FROM usersss WHERE username=?', [valid_username])
            result = cursor.fetchone()

            if result:
                if bcrypt.checkpw(valid_password.encode('utf-8'), result[0]):
                    frame.pack_forget()
                    login_success() 
                else:
                    CTkMessagebox(title="Alert", message="Invalid Password")
            else:
                CTkMessagebox(title="Alert", message="Invalid Username")
            
        else:
            CTkMessagebox(title="Alert", message="Enter all Data")



            

    
    checkbox = customtkinter.CTkCheckBox(master=frame, text="Remember Me")
    checkbox.pack(pady=12, padx=10)

    button1 = customtkinter.CTkButton(master=frame, text="Login", command=authentication)
    button1.pack(pady=12, padx=10)


    noaccount_label = customtkinter.CTkLabel(master=frame, text="Don't have an account ? ")
    noaccount_label.place(x=490, y=350)



    global noaccount_button
    noaccount_button = customtkinter.CTkButton(master=frame, text="Sign Up", font=font1, fg_color=None, width=20, height=20, hover_color="white", command=signup_window)
    noaccount_button.place(x=640, y=350)


def on_close():
    global window_open
    window_open = False
    register_window.destroy()
    noaccount_button.configure(state=customtkinter.NORMAL)



    




window_open = False
register_window = None

default_page()

    

root.mainloop()