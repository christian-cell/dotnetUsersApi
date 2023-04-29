Use DotNetCourseDatabase
GO

CREATE TABLE TutorialAppSchema.Auth (
    Email NVARCHAR(50)
    , PasswordHash VARBINARY(MAX)
    , PasswordSalt VARBINARY(MAX)
)