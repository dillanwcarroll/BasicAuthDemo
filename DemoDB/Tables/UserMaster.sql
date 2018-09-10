CREATE TABLE [dbo].[UserMaster]
(
	[Id] INT NOT NULL PRIMARY KEY, 
    [UserName] NVARCHAR(50) NOT NULL, 
    [Password] NVARCHAR(50) NOT NULL, 
    [IsActive] INT NOT NULL
)
