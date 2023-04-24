USE DotNetCourseDatabase
GO

SELECT 
    [UserId],
    [FirstName],
    [LastName],
    [Email],
    [Gender],
    [Active] 
FROM TutorialAppSchema.Users
GO

SELECT * FROM TutorialAppSchema.UserJobInfo
SELECT * FROM TutorialAppSchema.UserSalary