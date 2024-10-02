using System.ComponentModel.DataAnnotations;

namespace API.DTOs;

public class LoginDTO
{
    [MaxLength(100)]
    public required string Username {get; set;}

    public required string Password {get; set;}
}