import { IsString } from "class-validator";

export class RefreshTokenDto {

    @IsString({
        message: "token not string"
    })
    refreshToken: string
}