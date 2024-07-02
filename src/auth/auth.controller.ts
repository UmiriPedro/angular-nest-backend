import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards, Request } from '@nestjs/common';

import { AuthGuard } from './guards/auth.guard';
import { AuthService } from './auth.service';
import { CreateUserDto, LoginDto, RegisterUserDto } from './dto/index';
import { LoginResponse } from './interfaces/login-response';
import { JwtPayload } from './interfaces/jwt-payload';
import { User } from './entities/user.entity';

@Controller('auth')
export class AuthController {
  
  constructor(private readonly authService: AuthService) {}

  @Post()
  create(@Body() createUserDto: CreateUserDto) {
    return this.authService.create(createUserDto);
  }

  @Post('/login')
  login(@Body() loginDto: LoginDto) {
    return this.authService.login( loginDto );
  }

  @Post('/register')
  register(@Body() registerDto: RegisterUserDto) {
    return this.authService.register( registerDto );
  }

  @UseGuards( AuthGuard )
  @Get()
  findAll(@Request() req: Request) {
    return this.authService.findAll();
  }


  @UseGuards( AuthGuard )
  @Get('/check-token')
  checkToken(@Request() req: Request): LoginResponse {
    const user = req['user'] as User;

    return {
      user,
      token: this.authService.getJwtToken({ id: user._id })
    }
  }

}
