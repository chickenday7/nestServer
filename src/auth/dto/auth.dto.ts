import { IsEmail, IsString, MinLength } from "class-validator"

export class AuthDto {
    @IsString()
    login: string

    @MinLength(6, {
        message: "password too short (min:6 symbols)"
    })
    @IsString()
    password: string
}