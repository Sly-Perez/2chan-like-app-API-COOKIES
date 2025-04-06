# Weekie Mochi COOKIES API
Weekie Mochi is a 2chan-like app: It allows users to create posts, user profiles, comments and allows users to react to comments.<br>
This version of the API works with COOKIES to handle sessions. (they become third-party cookies as they are set in the API domain).

## Business Rules
- **Profiles**:
    - Only users with a profile can access to the endpoints of the api.
    - All User Profiles require a username, email and password.
    - The username of a user must not start with a number.
    - The username of a user can be, at most, 30 characters, and it can contain unicode characters.
    - The email of a user can be, at most, 100 characters, and it must not contain unicode characters.
    - The password of a user can be, at most, 30 characters, and it can contain unicode characters.
    - The inclusion of a custom profile picture is optional. A User will have a blank picture like other social media apps (facebook, etc.) by default.
    - In case there is the inclusion of a custom profile picture: The allowed formats are: "jpeg", "jpg", "webp", "gif" or "png".

- **Posts**:
    - All posts require a header and a description.
    - The header of a post can be, at most, 100 characters, and it can contain unicode characters.
    - The description of a post can be, at most, 1000 characters, and it can contain unicode characters.
    - The inclusion of image(s) is optional. A post can have no images.
    - In case there is the inclusion of image(s): The allowed formats are: "jpeg", "jpg", "webp", "gif" or "png". No more than 3 images can be uploaded by post.

- **Comments**:
    - All comments require a description.
    - The description of a comment can be, at most, 300 characters, and it can contain unicode characters.
    - The inclusion of image(s) is optional. A comment can have no images.
    - In case there is the inclusion of image(s): The allowed formats are: "jpeg", "jpg", "webp", "gif" or "png". No more than 3 images can be uploaded by comment.


## Tools Used:
This API was developed in **Plain/Vanilla PHP**, no third-party libraries used.

## Documentation
You have access to many endpoints. In the following document, we will show the endpoints available in the API, as well as their requirements and expected responses; They will be split into 2 categories:
1. **Authenticated Users**
    - Requests that can be made with no COOKIES (referring to the specific COOKIES set by the API after a user logs in) sent.
2. **Unauthenticated Users**
    - Requests that can only be made with COOKIES (referring to the specific COOKIES set by the API after a user logs in) sent.<br>

At the same time, the endpoints will be separated by entity in the database to facilitate an object-oriented comprehension.

## Unauthenticated Users
### <ins>Users</ins>
#### 1. Create User Profile
It allows you to create a user profile. The requirements vary whether you upload or not a custom profile picture.<br>

**POST Request to endpoint:**<br>
/users/signup

- **Profile with no custom profile picture requirements**:
    - Build a JSON body with the mandatory data for a user: username, email, password.
    - Send the JSON body directly as a JSON object to the endpoint. <br>

**Example :**
```
{
    "username": "test1",
    "email": "test1@example.ca",
    "password": "test1pass"
}
```
- **Profile with custom profile picture requirements**:
    - Build a form-data object.
    - Append a JSON body to the form-data object with the mandatory data for a user: username, email, password.<br>
    *[The appended JSON body **must** be named "jsonBody"]*
    - Append the corresponding image to the form-data object. <br>
    *[The appended image **must** be named "picture"]*
    - Send the form-data object to the endpoint.

**Expected response:**<br>
If everything went well, the API should send back the basic information of the created user and a **201** status code.
```
[Content-Type: "application/json"]
{
    "userId": 17,
    "username": "test1",
    "picture": "blank-profile-picture.webp",
    "joinedAt": "2025-03-30 13:30:56",
    "amountOfPosts": 0,
    "hierarchyLevelId": 2
}
```
**Expected exception response:**<br>
If any of the fields of the given data is invalid, the API should send back a JSON body with the information of the error and a **400** status code.
```
[Content-Type: "application/json"]
{
    "errors": ["error1", "error2", "error3"]
}
```
**Note:**  
*[You can send a form-data object in both scenarios. However, the appended JSON object **must** be named "jsonBody"]*

#### 2. Log In with user profile
It allows you to log in with user credentials. The requirements don't vary depending on the situation.<br>

**POST Request to endpoint:**<br>
/users/login

- **Requirements**:
    - Build a JSON body with the mandatory data to log in: username, email.
    - Send the JSON body directly as a JSON object to the endpoint. <br>

**Example :**
```
{
    "email": "test1@example.ca",
    "password": "test1pass"
}
```

**Expected response:**<br>
If everything went well, the API should send back a JSON body similar to the following and a **200** status code.
```
[Content-Type: "application/json"]
{
    "message": "User logged in successfully"
}
```

**Expected exception response:**<br>
If the user credentials are invalid, the API should send back a JSON body with the information of the error and a **400** status code.
```
[Content-Type: "application/json"]
{
    "errors": ["error1"]
}
```

**Note:**<br> 
*[You can also send a form-data object. However, the appended JSON object **must** be named "jsonBody]*



## Authenticated Users
*[All requests made from here on need to be sent along with the corresponding COOKIES, which will be automatically set by the API after the client logs in]*
### <ins>Users</ins>
#### 1. Log Out
It allows you to log out. The requirements don't vary depending on the situation.<br>

**POST Request to endpoint:**<br>
/users/logout

- **Requirements**:
    - Do not send any bodies nor objects.

**Expected response:**<br>
If everything went well, the API should send back a JSON body similar to the following and a **200** status code.
```
[Content-Type: "application/json"]
{
    "message": "User logged out successfully"
}
```

**Expected exception response:**<br>
*[This endpoint does not count with a specific exception response]*

**Note:**  
*[You can send an object (JSON or form-data). However, it will not be taken into account because it is not useful in this request]*


#### 2. Get information of the logged-in profile
It allows you get the information of the user in session. The requirements don't vary depending on the situation.<br>

**GET Request to endpoint:**<br>
/users/my/profile

- **Requirements**:
    - Do not send any bodies nor objects.

**Expected response:**<br>
If everything went well, the API should send back a JSON body with the information of the logged-in user and a **200** status code.
```
[Content-Type: "application/json"]
{
    "userId": 17,
    "username": "test1",
    "email": "test1@example.ca",
    "picture": "blank-profile-picture.webp",
    "joinedAt": "2025-03-30 13:30:56",
    "amountOfPosts": 0,
    "hierarchyLevelId": 2
}
```

**Expected exception response:**<br>
*[This endpoint does not count with a specific exception response]*

**Note:**  
*[You can send an object (JSON or form-data). However, it will not be taken into account because it is not useful in this request]*

#### 3. Edit information of the logged-in profile
It allows you edit the information of the user in session. The requirements vary whether you upload or not a custom profile picture.<br>

**POST Request to endpoint:**<br>
/users/my/profile

- **Update with no custom profile picture requirements**:
    - Build a JSON body with any fields you want to update in the profile: username, email or password.
    - Send the JSON body directly as a JSON object to the endpoint.

**Example:**
```
[Content-Type: "application/json"]
{
    "username": "test1updated",
    "password": "test1passupdated"
}
```
- **Update with custom profile picture requirements**:
    - Build a form-data object.
    - Append a JSON body to the form-data object with any fields you want to update in the profile: username, email or password.<br>
    *[The appended JSON body **must** be named "jsonBody"]*
    - Append the corresponding image to the form-data object. <br>
    *[The appended image **must** be named "picture"]*
    - Send the form-data object to the endpoint.

**Expected response:**<br>
If everything went well, the API should send back a JSON body with the information of the user and a **200** status code.
```
[Content-Type: "application/json"]
{
    "userId": 17,
    "username": "test1updated",
    "email": "test1@example.ca",
    "picture": "blank-profile-picture.webp",
    "joinedAt": "2025-03-30 13:30:56",
    "amountOfPosts": 0,
    "hierarchyLevelId": 2
}
```

**Expected exception response:**<br>
If any of the fields intended to update is invalid, the API should send back a JSON body with the information of the error and a **400** status code.
```
[Content-Type: "application/json"]
{
    "errors": ["error1", "error2", "error3"]
}
```
**Note:**<br>
*[You can send no objects (neither JSON nor form-data). The profile will still be updated, but with no changes as no data was given]*<br>
*[In case any of the fields is given, the API will validate properly each of them]*<br>
*[You can send a form-data object in both scenarios. However, the appended JSON object **must** be named "jsonBody"]*<br>

#### 4. Delete the logged-in profile
It allows you to delete the logged-in user. The requirements don't vary depending on the situation.<br>

**DELETE Request to endpoint:**<br>
/users/my/profile

- **Requirements**:
    - Do not send any bodies nor objects.
    - The "hierarchyLevelId" field of your profile **must** be 2. <br>
    *[2 -> <ins>Regular User</ins>, 1 -> <ins>Administrator</ins>]*.

**Expected response:**<br>
If everything went well, the API should send back a JSON body similar to the following and a **200** status code.
```
[Content-Type: "application/json"]
{
    "message": [
        "Your profile was deleted successfully"
    ]
}
```

**Expected exception response:**<br>
If the "hierarchyLevelId" field of your profile is 1, it implies you are an administrator. An Administrator is forbbiden to delete their profile. The API should send back a JSON body similar to the following and a **403** status code.
```
[Content-Type: "application/json"]
{
    "errors": ["Administrators Cannot delete their own profile"]
}
```
**Note:**  
*[You can send an object (JSON or form-data). However, it will not be taken into account because it is not useful in this request]*

#### 5. Get information of a user
It allows you to get the information of any user registered in the weekieMochi Database. The requirements don't vary depending on the situation.<br>

**GET Request to endpoint:**<br>
/users/:id<br>
*[":id" being a placeholder for the user id]*

- **Requirements**:
    - Do not send any bodies nor objects.

**Expected response:**<br>
If everything went well, the API should send back a JSON body with the information of the user and a **200** status code.
```
[Content-Type: "application/json"]
[path: "/users/10"]
{
    "userId": 10,
    "username": "张三丰",
    "picture": "profile-picture-ni6392bf93023.jpg",
    "joinedAt": "2025-03-30 12:37:50",
    "amountOfPosts": 2,
    "hierarchyLevelId": 2
}
```

**Expected exception response:**<br>
If no user with the given id exists, the API should send back a JSON body with the information of the error and a **404** status code.
```
[Content-Type: "application/json"]
[path: "/users/fakeid"]
{
    "errors": ["User with id fakeid was not found"]
}
```
**Note:**  
*[You can send an object (JSON or form-data). However, it will not be taken into account because it is not useful in this request]*

#### 6. Get profile picture of a user
It allows you to get the profile picture of any user registered in the weekieMochi Database. The requirements don't vary depending on the situation.<br>

**GET Request to endpoint:**<br>
/users/:id/pictures<br>
*[":id" being a placeholder for the user id]*

- **Requirements**:
    - Do not send any bodies nor objects.

**Expected response:**<br>
If everything went well, the API should send back the picture of the user and a **200** status code.
```
[Content-Type: "image/gif"]
[path: "/users/666/pictures"]
\Profile picture of the user/
```

**Expected exception response:**<br>
If the picture of the user does exist, but the server is not able to find it, the API should send back an image explaining the error and a **404** status code.
```
[Content-Type: "image/webp"]
[path: "/users/667/pictures"]
\Exception Image/
```
**Note:**  
*[The Content-Type header will not always be "image/gif", it will vary depending on what the MIME type of the picture is, which, at the same time, will be aligned to the allowed formats; In the case of the 404 error, it will always be "image/webp" unless it is changed by developers.]*<br>
*[You can send an object (JSON or form-data). However, it will not be taken into account because it is not useful in this request]*

#### 7. Get blank user profile picture
It allows you to get a picture of a blank user (like on other social media apps; e.g. Facebook and similars). The requirements don't vary depending on the situation.<br>

**GET Request to endpoint:**<br>
/users/zero/pictures

- **Requirements**:
    - Do not send any bodies nor objects.

**Expected response:**<br>
If everything went well, the API should send back a picture of a blank user and a **200** status code.
```
[Content-Type: "image/webp"]
\Blank User profile picture/
```

**Expected exception response:**<br>
*[This endpoint does not count with a specific exception response]*

**Note:**  
*[The Content-Type header will always be "image/webp" unless it is changed by developers.]*<br>
*[You can send an object (JSON or form-data). However, it will not be taken into account because it is not useful in this request]*

#### 8. Delete profile of a user
It allows you to delete the profile of any user. The requirements don't vary depending on the situation.<br>

**DELETE Request to endpoint:**<br>
/users/:id<br>
*["id" being a placeholder for the user id]*

- **Requirements**:
    - Do not send any bodies nor objects.
    - The "hierarchyLevelId" field of your profile **must** be 1.<br>
    *[2 -> <ins>Regular User</ins>, 1 -> <ins>Administrator</ins>].*<br>
    *[**JUST** an Administrator has access to this endpoint].*
    - The "userId" field of your profile **must** be different than the id sent in the path. <br>
    *[An Administrator **cannot** delete their own profile. To do so, they need to execute a query in the database manually].*
    - The "hierarchyLevelId" field of the profile of the user with the id sent in the path **must** be 2.<br>
    *[An Administrator can **just** delete Regular User profiles, not Administrator profiles].*

**Expected response:**<br>
If everything went well, the API should send back a picture of a blank user and a **200** status code.
```
[Content-Type: "application/json"]
[path: "/users/999"]
{
    "message": "User with id 999 deleted successfully"
}
```

**Expected Exception response 1:**<br>
If the "hierarchyLevelId" field of your profile is not 1, the API should send back no bodies and a **403** status code.
```
[Content-Type: "application/json"]
```

**Expected Exception response 2:**<br>
If the "userId" field of your profile is the same as the id sent in the path, the API should send back a JSON body similar to the following a **403** status code.
```
[Content-Type: "application/json"]
{
    "errors": ["Administrators Cannot delete their own profile"]
}
```

**Expected Exception response 3:**<br>
If the "hierarchyLevelId" field of the profile of the user with the id sent in the path is not 2, the API should send back a JSON body similar to the following a **403** status code.
```
[Content-Type: "application/json"]
{
    "errors": ["Cannot delete other administrators' profiles"]
}
```

**Note:**  
*[You can send an object (JSON or form-data). However, it will not be taken into account because it is not useful in this request]*

### <ins>Posts</ins>

#### 1. Create Post
It allows you to create a post. The requirements vary whether you attach or not images to the post.<br>

**POST Request to endpoint:**<br>
/posts/

- **Post with no images attached**:
    - Build a JSON body with the mandatory data for a post: header and description.
    - Send the JSON body directly as a JSON object to the endpoint. <br>

**Example :**
```
{
  "header": "test 1 header",
  "description": "test 1 description"
}
```
- **Post with images attached**:
    - Build a form-data object.
    - Append a JSON body to the form-data object with the mandatory data for a post: header and description.<br>
    *[The appended JSON body **must** be named "jsonBody"]*
    - Append the corresponding images to the form-data object as an array. <br>
    *[The appended array **must** be named "pictures"]*
    - Send the form-data object to the endpoint.

**Expected response:**<br>
If everything went well, the API should send back the basic information of the created post and a **201** status code.
```
[Content-Type: "application/json"]
{
  "postId": 1,
  "header": "test 1 header",
  "description": "test 1 description",
  "publishDatetime": "2025-04-04 09:39:55",
  "commentsQuantity": 0,
  "numberOfImages": 0,
  "userId": 1
}
```
**Expected exception response:**<br>
If any of the fields of the given data is invalid, the API should send back a JSON body with the information of the error and a **400** status code.
```
[Content-Type: "application/json"]
{
    "errors": ["error1", "error2"]
}
```
**Note:**  
*[You can send a form-data object in both scenarios. However, the appended JSON object **must** be named "jsonBody"]*

#### 2. Get information of all posts
It allows you to get the information of all existing posts in the weekieMochi Database. The requirements don't vary depending on the situation.<br>

**GET Request to endpoint:**<br>
/posts/

- **Requirements**:
    - Do not send any bodies nor objects.

**Expected response:**<br>
If everything went well, the API should send back an array of JSON objects with the information of all the posts and a **200** status code.
```
[Content-Type: "application/json"]
[
    {
    "postId": 2,
    "header": "test 2 header",
    "description": "test 2 description",
    "publishDatetime": "2025-03-31 23:24:03",
    "commentsQuantity": 5,
    "numberOfImages": 0,
    "userId": 2
    },
    {
    "postId": 1,
    "header": "test 1 header",
    "description": "test 1 description",
    "publishDatetime": "2025-03-31 23:24:03",
    "commentsQuantity": 5,
    "numberOfImages": 1,
    "userId": 1
    }
]
```

**Expected exception response:**<br>
*[This endpoint does not count with a specific exception response]*

**Note:**  
*[You can send an object (JSON or form-data). However, it will not be taken into account because it is not useful in this request]*<br>
*[In case there are 0 posts, you will receive an empty array as a response]*

#### 3. Get All posts of the logged-in user
It allows you to get the information of all posts created by the logged-in user. The requirements don't vary depending on the situation.<br>

**GET Request to endpoint:**<br>
/posts/my/list

- **Requirements**:
    - Do not send any bodies nor objects.

**Expected response:**<br>
If everything went well, the API should send back an array of JSON objects with the information of all the posts created by the logged-in user and a **200** status code.
```
[Content-Type: "application/json"]
[
    {
    "postId": 2,
    "header": "test 2 header",
    "description": "test 2 description",
    "publishDatetime": "2025-03-31 23:24:03",
    "commentsQuantity": 5,
    "numberOfImages": 0,
    "userId": 2
    }
]
```

**Expected exception response:**<br>
*[This endpoint does not count with a specific exception response]*

**Note:**  
*[You can send an object (JSON or form-data). However, it will not be taken into account because it is not useful in this request]*<br>
*[In case there are 0 posts, you will receive an empty array as a response]*

#### 4. Get information of a post
It allows you to get the information of any post registered in the weekieMochi Database. The requirements don't vary depending on the situation.<br>

**GET Request to endpoint:**<br>
/posts/:id<br>
*[":id" being a placeholder for the post id]*

- **Requirements**:
    - Do not send any bodies nor objects.

**Expected response:**<br>
If everything went well, the API should send back a JSON body with the information of the post and a **200** status code.
```
[Content-Type: "application/json"]
[path: "/posts/10"]
{
  "postId": 10,
  "header": "test 10 header",
  "description": "test 10 description",
  "publishDatetime": "2025-03-31 23:24:03",
  "commentsQuantity": 5,
  "numberOfImages": 0,
  "userId": 1
}
```

**Expected exception response:**<br>
If no post with the given id exists, the API should send back a JSON body with the information of the error and a **404** status code.
```
[Content-Type: "application/json"]
[path: "/posts/fakeid"]
{
    "errors": ["Post with id fakeid was not found"]
}
```
**Note:**  
*[You can send an object (JSON or form-data). However, it will not be taken into account because it is not useful in this request]*

#### 5. Get an image attached to a post
It allows you to get an image attached to a post. The requirements don't vary depending on the situation.<br>

**GET Request to endpoint:**<br>
/posts/:id/pictures/:position<br>
*[":id" being a placeholder for the post id]*<br>
*[":position" being a placeholder for the position of the image. e.g; 1, 2 or 3. It is index + 1]*

- **Requirements**:
    - Do not send any bodies nor objects.

**Expected response:**<br>
If everything went well, the API should send back the corresponding image attached to the post and a **200** status code.
```
[Content-Type: "image/png"]
[path: "/posts/666/pictures/2"]
\Image number 2 attached to the post/
```

**Expected exception response 1:**<br>
If the image attached to the post at the indicated position does not exist, the API should send back a JSON body with the information of the error and a **404** status code.
```
[Content-Type: "application/json"]
[path: "/posts/666/pictures/3"]
{
    "errors"=>["image number 3 attached to post with id 666 was not found"]
}
```

**Expected exception response 2:**<br>
If the corresponding image attached to the post does exist, but the server is not able to find it, the API should send back an image explaining the error and a **404** status code.
```
[Content-Type: "image/webp"]
[path: "/posts/999/pictures/1"]
\Exception Image/
```
**Note:**  
*[The Content-Type header will not always be "image/png", it will vary depending on what the MIME type of the picture is, which, at the same time, will be aligned to the allowed formats; In the case of the **Expected exception response 2**, it will always be "image/webp" unless it is changed by developers.]*<br>
*[You can send an object (JSON or form-data). However, it will not be taken into account because it is not useful in this request]*

#### 6. Delete post
It allows you to delete a post. The requirements vary whether you want to delete a post of yours or a post of another user.<br>

**DELETE Request to endpoint:**<br>
/posts/:id<br>
*["id" being a placeholder for the post id]*

- **Delete a post of yours Requirements**:
    - Do not send any bodies nor objects.
    - The "userId" field of your profile **must** be the same as the "userId" field of the post to delete. <br>

- **Delete another user's post Requirements**:
    - Do not send any bodies nor objects.
    - The "userId" field of your profile **must** be different than the "userId" field of the post to delete.<br>
    - The "hierarchyLevelId" field of your profile **must** be 1.<br>
    *[2 -> <ins>Regular User</ins>, 1 -> <ins>Administrator</ins>].*<br>
    *[**JUST** an Administrator can delete other users' posts].*

**Expected response:**<br>
If everything went well, the API should send back a picture of a blank user and a **200** status code.
```
[Content-Type: "application/json"]
[path: "/posts/999"]
{
    "message": "Post with id 999 deleted successfully"
}
```

**Expected Exception response 1:**<br>
If the "userId" field of the post is not the same as the "userId" field of your profile and the "hierarchyLevelId" field of your profile is not 1, the API should send back no bodies and a **403** status code.
```
[Content-Type: "application/json"]
```

**Note:**  
*[You can send an object (JSON or form-data). However, it will not be taken into account because it is not useful in this request]*


### <ins>Comments</ins>

A Key concept that will be often used in this section is the difference between **main comments** and **replies**:
1. **Main comment.**
    - It is an independent comment.
    - It can have a list of replies attached to it.
    - If it is deleted, so will the replies attached to it.

2. **Reply.**
    - It is a dependent comment.
    - It is always attached to a main comment.
    - If the main comment that it is attached to it is deleted, so will it.

#### 1. Create Main Comment on a post
It allows you to create a Main comment on a post. The requirements vary whether you attach or not images to the post.<br>

**POST Request to endpoint:**<br>
/posts/:id/comments<br>
*[":id" being a placeholder for the post id]*

- **Main comment with no images attached**:
    - Build a JSON body with the mandatory data for a comment: description.
    - Send the JSON body directly as a JSON object to the endpoint. <br>

**Example:**
```
{
  "description": "test comment 1 description"
}
```
- **Main comment with images attached**:
    - Build a form-data object.
    - Append a JSON body to the form-data object with the mandatory data for a comment: description.<br>
    *[The appended JSON body **must** be named "jsonBody"]*
    - Append the corresponding images to the form-data object as an array. <br>
    *[The appended array **must** be named "pictures"]*
    - Send the form-data object to the endpoint.

**Expected response:**<br>
If everything went well, the API should send back the basic information of the created Main comment and a **201** status code.
```
[Content-Type: "application/json"]
[path: "/posts/11/comments"]
{
    "commentId": 57,
    "description": "test comment 1 description",
    "publishDatetime": "2025-04-04 10:14:21",
    "likesQuantity": 0,
    "dislikesQuantity": 0,
    "repliesQuantity": 0,
    "numberOfImages": 0,
    "userId": 18,
    "postId": 11,
    "responseTo": null
}
```

**Expected exception response 1:**<br>
If no post with the given id exists, the API should send back a JSON body with the information of the error and a **404** status code.
```
[Content-Type: "application/json"]
[path: "/posts/fakeid/comments"]
{
    "errors": ["Post with id fakeid was not found"]
}
```

**Expected exception response 2:**<br>
If any of the fields of the given data is invalid, the API should send back a JSON body with the information of the error and a **400** status code.
```
[Content-Type: "application/json"]
{
    "errors": ["error1"]
}
```
**Note:**  
*[You can send a form-data object in both scenarios. However, the appended JSON object **must** be named "jsonBody"]*

#### 2. Get All main comments of a post
It allows you to get the information of all the main comments of a post. The requirements don't vary depending on the situation.<br>

**GET Request to endpoint:**<br>
/posts/:id/comments<br>
*[":id" being a placeholder for the post id]*

- **Requirements**:
    - Do not send any bodies nor objects.

**Expected response:**<br>
If everything went well, the API should send back an array of JSON objects with the information of all the Main comments created on the post and a **200** status code.
```
[Content-Type: "application/json"]
[path: "/posts/11/comments"]
[
  {
    "commentId": 57,
    "description": "test comment 1 description",
    "publishDatetime": "2025-04-04 10:14:21",
    "likesQuantity": 0,
    "dislikesQuantity": 0,
    "repliesQuantity": 0,
    "numberOfImages": 0,
    "userId": 18,
    "postId": 11,
    "responseTo": null
  },
  {
    "commentId": 58,
    "description": "test comment 2 description",
    "publishDatetime": "2025-04-04 10:17:11",
    "likesQuantity": 0,
    "dislikesQuantity": 0,
    "repliesQuantity": 0,
    "numberOfImages": 0,
    "userId": 18,
    "postId": 11,
    "responseTo": null
  }
]
```

**Expected exception response:**<br>
If no post with the given id exists, the API should send back a JSON body with the information of the error and a **404** status code.
```
[Content-Type: "application/json"]
[path: "/posts/fakeid/comments"]
{
    "errors": ["Post with id fakeid was not found"]
}
```

**Note:**  
*[You can send an object (JSON or form-data). However, it will not be taken into account because it is not useful in this request]*<br>
*[In case there are 0 main comments, you will receive an empty array as a response]*

#### 3. Create Reply for a Main comment
It allows you to create a reply for a Main comment. The requirements vary whether you attach or not images to the post.<br>

**POST Request to endpoint:**<br>
/comments/:id/replies<br>
*[":id" being a placeholder for the Main comment id]*

- **Reply with no images attached**:
    - Build a JSON body with the mandatory data for a comment: description.
    - Send the JSON body directly as a JSON object to the endpoint. <br>

**Example:**
```
{
  "description": "test reply 1 description"
}
```
- **Reply with images attached**:
    - Build a form-data object.
    - Append a JSON body to the form-data object with the mandatory data for a comment: description.<br>
    *[The appended JSON body **must** be named "jsonBody"]*
    - Append the corresponding images to the form-data object as an array. <br>
    *[The appended array **must** be named "pictures"]*
    - Send the form-data object to the endpoint.

**Expected response:**<br>
If everything went well, the API should send back the basic information of the created reply and a **201** status code.
```
[Content-Type: "application/json"]
[path: "/comments/57/replies"]
{
  "commentId": 59,
  "description": "test reply 1 description",
  "publishDatetime": "2025-04-04 11:21:47",
  "likesQuantity": 0,
  "dislikesQuantity": 0,
  "repliesQuantity": 0,
  "numberOfImages": 0,
  "userId": 20,
  "postId": 11,
  "responseTo": 57
}
```

**Expected exception response 1:**<br>
If no Main comment with the given id exists, the API should send back a JSON body with the information of the error and a **404** status code.
```
[Content-Type: "application/json"]
[path: "/comments/fakeid/replies"]
{
    "errors": ["Main Comment with id fakeid was not found"]
}
```

**Expected exception response 2:**<br>
If any of the fields of the given data is invalid, the API should send back a JSON body with the information of the error and a **400** status code.
```
[Content-Type: "application/json"]
{
    "errors": ["error1"]
}
```
**Note:**  
*[You can send a form-data object in both scenarios. However, the appended JSON object **must** be named "jsonBody"]*

#### 4. Get All replies of a Main comment
It allows you to get the information of all the replies of a Main comment. The requirements don't vary depending on the situation.<br>

**GET Request to endpoint:**<br>
/comments/:id/replies<br>
*[":id" being a placeholder for the main comment id]*

- **Requirements**:
    - Do not send any bodies nor objects.

**Expected response:**<br>
If everything went well, the API should send back an array of JSON objects with the information of all the replies of the Main comments and a **200** status code.
```
[Content-Type: "application/json"]
[path: "comments/57/replies"]
[
  {
    "commentId": 59,
    "description": "test reply 1 description",
    "publishDatetime": "2025-04-04 11:21:47",
    "likesQuantity": 0,
    "dislikesQuantity": 0,
    "repliesQuantity": 0,
    "numberOfImages": 0,
    "userId": 1,
    "postId": 11,
    "responseTo": 57
  },
  {
    "commentId": 60,
    "description": "test reply 2 description",
    "publishDatetime": "2025-04-04 11:22:02",
    "likesQuantity": 0,
    "dislikesQuantity": 0,
    "repliesQuantity": 0,
    "numberOfImages": 0,
    "userId": 1,
    "postId": 11,
    "responseTo": 57
  }
]
```

**Expected exception response:**<br>
If no main comment with the given id exists, the API should send back a JSON body with the information of the error and a **404** status code.
```
[Content-Type: "application/json"]
[path: "/comments/fakeid/replies"]
{
    "errors": ["Main Comment with id fakeid was not found"]
}
```

**Note:**  
*[You can send an object (JSON or form-data). However, it will not be taken into account because it is not useful in this request]*<br>
*[In case there are 0 replies, you will receive an empty array as a response]*

#### 5. Get an image attached to a comment
It allows you to get an image attached to a comment (no matter if it is a Main comment or a reply). The requirements don't vary depending on the situation.<br>

**GET Request to endpoint:**<br>
/comments/:id/pictures/:position<br>
*[":id" being a placeholder for the comment id]*<br>
*[":position" being a placeholder for the position of the image. e.g; 1, 2 or 3. It is index + 1]*

- **Requirements**:
    - Do not send any bodies nor objects.

**Expected response:**<br>
If everything went well, the API should send back the corresponding image attached to the comment and a **200** status code.
```
[Content-Type: "image/png"]
[path: "/comments/666/pictures/1"]
\Image number 1 attached to the post/
```

**Expected exception response 1:**<br>
If the image attached to the comment at the indicated position does not exist, the API should send back a JSON body with the information of the error and a **404** status code.
```
[Content-Type: "application/json"]
[path: "/comments/666/pictures/2"]
{
    "errors"=>["image number 2 attached to comment with id 666 was not found"]
}
```

**Expected exception response 2:**<br>
If the corresponding image attached to the comment does exist, but the server is not able to find it, the API should send back an image explaining the error and a **404** status code.
```
[Content-Type: "image/webp"]
[path: "/comments/999/pictures/1"]
\Exception Image/
```
**Note:**  
*[The Content-Type header will not always be "image/png", it will vary depending on what the MIME type of the picture is, which, at the same time, will be aligned to the allowed formats; In the case of the **Expected exception response 2**, it will always be "image/webp" unless it is changed by developers.]*<br>
*[You can send an object (JSON or form-data). However, it will not be taken into account because it is not useful in this request]*

#### 6. Delete comment
It allows you to delete a comment. The requirements vary whether you want to delete a comment of yours or a comment of another user (no matter if it is a Main comment or a reply).<br>

**DELETE Request to endpoint:**<br>
/comments/:id<br>
*["id" being a placeholder for the comment id]*

- **Delete a comment of yours Requirements**:
    - Do not send any bodies nor objects.
    - The "userId" field of your profile **must** be the same as the "userId" field of the comment to delete. <br>

- **Delete another user's comment Requirements**:
    - Do not send any bodies nor objects.
    - The "userId" field of your profile **must** be different than the "userId" field of the post to delete.<br>
    - The "hierarchyLevelId" field of your profile **must** be 1.<br>
    *[2 -> <ins>Regular User</ins>, 1 -> <ins>Administrator</ins>].*<br>
    *[**JUST** an Administrator can delete other users' comments].*

**Expected response:**<br>
If everything went well, the API should send back a picture of a blank user and a **200** status code.
```
[Content-Type: "application/json"]
[path: "/comments/999"]
{
    "message": "Comment with id 999 deleted successfully"
}
```

**Expected Exception response 1:**<br>
If the "userId" field of the comment is not the same as the "userId" field of your profile and the "hierarchyLevelId" field of your profile is not 1, the API should send back no bodies and a **403** status code.
```
[Content-Type: "application/json"]
```

**Note:**  
*[You can send an object (JSON or form-data). However, it will not be taken into account because it is not useful in this request]*

### <ins>Comment Reactions</ins>

A Key concept to know is that a comment Reaction as such have two fields when created:
1. **isLike.**
    - It indicates whether a comment Reaction is a like or not.
    - Its data type is BIT.<br>
    *[0 -> <ins>it is not a like</ins>, 1 -> <ins>it is a like</ins>]*

2. **isDislike.**
    - It indicates whether a comment Reaction is a dislike or not.
    - Its data type is BIT.<br>
    *[0 -> <ins>it is not a dislike</ins>, 1 -> <ins>it is a dislike</ins>]*

*[In case both fields are equals 0, it will mean the comment Reaction it is neither a like nor a dislike.]*<br>
*[There will not ever be a double reaction such as a isDislike = 1 and a isLike = 1. The Database optimizations (stored procedures and triggers) will make sure of it].*

#### 1. Create or update Comment reaction of the logged-in user to a comment
It allows you to create or update the information of the comment Reaction of the logged-in user to a comment (no matter if it is a Main comment or a reply). The requirements don't vary depending on the situation.<br>
*[You do not need to specify if you will create or update a comment Reaction. The Database optimizations (stored procedures and triggers) will do the corresponding operations]*

**POST Request to endpoint:**<br>
/comments/:id/my/reactions<br>
*[":id" being a placeholder for the comment id]*

- **Requirements**:
    - Build a JSON body with the mandatory data for a comment Reaction: isLike or isDislike.
    - Do not send a double reaction.<br>
    *[Even if both reactions are equals 0]*
    - Send the JSON body directly as a JSON object to the endpoint. <br>

**Example:**
```
{
  "isLike": 1
}
```

**Expected response:**<br>
If everything went well, the API should send back a JSON object with the information of the comment Reaction of the logged-in user to the comment and a **200** status code.
```
[Content-Type: "application/json"]
[path: "comments/57/my/reactions"]
{
  "userId": 18,
  "commentId": 57,
  "isLike": 1,
  "isDislike": 0
}
```

**Expected exception response 1:**<br>
If no comment with the given id exists, the API should send back a JSON body with the information of the error and a **404** status code.
```
[Content-Type: "application/json"]
[path: "/comments/fakeid/my/reactions"]
{
    "errors": ["Comment with id fakeid was not found"]
}
```

**Expected exception response 2:**<br>
If any of the fields of the given data is invalid, the API should send back a JSON body with the information of the error and a **400** status code.
```
[Content-Type: "application/json"]
[path: "/comments/fakeid/my/reactions"]
{
    "errors": ["error1"]
}
```

**Note:**  
*[You can send a form-data object. However, the appended JSON object must be named "jsonBody"]*

#### 2. Get Comment reaction of the logged-in user to a comment
It allows you to get the information of a comment Reaction of the logged-in user to a comment. The requirements don't vary depending on the situation.<br>

**GET Request to endpoint:**<br>
/comments/:id/my/reactions<br>
*[":id" being a placeholder for the main comment id]*

- **Requirements**:
    - Do not send any bodies nor objects.

**Expected response:**<br>
If everything went well, the API should send back an array of JSON objects with the information of the comment Reaction of the logged-in user to the comment and a **200** status code.
```
[Content-Type: "application/json"]
{
  "commentId": 57,
  "userId": 18,
  "isLike": 1,
  "isDislike": 0
}
```

**Expected exception response 1:**<br>
If no comment with the given id exists, the API should send back a JSON body with the information of the error and a **404** status code.
```
[Content-Type: "application/json"]
[path: "/comments/fakeid/replies"]
{
    "errors": ["Comment with id fakeid was not found"]
}
```

**Expected exception response 2:**<br>
If no comment Reaction of the logged-in user to the comment exists, the API should send back a JSON body with the information of the error and a **404** status code.
```
[Content-Type: "application/json"]
[path: "/comments/666/my/reactions"]
{
    "errors": ["Comment reaction with user Id 18 and comment Id 666 was not found"]
}
```

**Note:**  
*[You can send an object (JSON or form-data). However, it will not be taken into account because it is not useful in this request]*

