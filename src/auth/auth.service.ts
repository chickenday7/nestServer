import { BadRequestException, HttpCode, Injectable, UnauthorizedException, UsePipes, ValidationPipe } from '@nestjs/common';
import { ModelType } from '@typegoose/typegoose/lib/types';
import { InjectModel } from 'nestjs-typegoose';
import { UserModel } from 'src/user/user.model';
import { AuthDto } from './dto/auth.dto';
import {hash, genSalt, compare} from "bcryptjs"
import { JwtService } from '@nestjs/jwt';


@Injectable()
export class AuthService {
    constructor(@InjectModel(UserModel) private readonly UserModel: ModelType<UserModel>, private readonly jwtService: JwtService){

    }

    async login(dto: AuthDto){
        const user = await this.validateUser(dto)
        
        const tokens = await this.issueTokenPair(String(user._id))

        return {user, tokens}
    }

    async register(dto: AuthDto)  {
        const oldUser = await this.UserModel.findOne({login: dto.login})
        if(oldUser){
            throw new BadRequestException("Пользователь с этим логином уже существует в системе")
        }
        const salt = await genSalt(10)

    
        const newUser = new this.UserModel({
            login: dto.login,
            password: await hash(dto.password, salt)
        })

        const tokens = await this.issueTokenPair(String(newUser._id))

        return {
            user: this.returnUserFields(newUser),
            ...tokens
        }
    }

    async validateUser(dto: AuthDto):Promise<UserModel>{
        const user = await this.UserModel.findOne({login: dto.login})
        if(!user){
            throw new UnauthorizedException("Пользователь не был найден")
        }
                
        const isValidPassword = await compare(dto.password, user.password)
        if(!isValidPassword) {
            throw new UnauthorizedException("Пароль неверный")
        }

        return user
    }

    async issueTokenPair(userId: string){
        const data = {_id: userId}

        const refreshToken = await this.jwtService.signAsync(data, {
            expiresIn: "15d"
        })

        const accessToken = await this.jwtService.signAsync(data, {
            expiresIn: "1h"
        })

        return {refreshToken, accessToken}
    }

    returnUserFields(user: UserModel){
        return {
            _id: user._id,
            login: user.login,
            isAdmin: user.isAdmin
        }
    }

}
