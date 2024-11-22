# This is a rough guide for contributing to this repository

# Fork the repo into your own GitHub account
* In your browser go to https://github.com/GLEIF-IT/vlei-verifier
* Click the "Fork" button in the top right corner of the page
* Fork the repo into your own GitHub account
![Fork the repo](image-1.png)
![Your fork](image-2.png)

# Start from main
* From your terminal or IDE, clone your forked repo
```
git clone https://github.com/2byrds/vlei-verifier.git
```
* Confirm you are starting from the main branch
```
git status
```
![Start from main](image.png)

# Create new branch
* Switch from main, creating a new branch [semantically named](https://gist.github.com/seunggabi/87f8c722d35cd07deb3f649d45a31082#file-semantic-branch-names-md) to something like 'docs/contrib_guide'

```
git switch -c "test/auth_eba_admin"
```
![switch to new branch](image-3.png)

# Add/Commit the changes to the branch
* Git add your changes and commit them. Note that the -s flag signs the commit and the -S flag signs the commit with a GPG key. That is currently optional but preffered.
```
git add docs
```
![git add the files](image-4.png)

```
git commit -s -S -m"Added docs folder and CONTRIBUTE guide"
```
![alt text](image-5.png)

# Push the changes to your fork
```git push 2byrds```
![alt text](image-6.png)

# Create a pull request
* Go to your forked repo in your browser
* Click the "New pull request" button
* Set the reviewer to 2byrds (or whoever you want to review your changes)
* Add a title and description
* Set yourself as the assignee
* Click "Create draft pull request" until it is ready for final review
* Click "Ready for review" when you are ready for the reviewer to look at the changes to be merged
![alt text](image-7.png)
![alt text](image-8.png)

# Respond to the reviewers questions/comments/requests
* Note there are several automated checks that must all pass

# Once approved the merge request will be merged