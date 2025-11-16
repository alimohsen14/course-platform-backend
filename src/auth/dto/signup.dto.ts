/* eslint-disable */
import { IsEmail, IsNotEmpty, MinLength, IsString } from 'class-validator';

export class SignupDto {
  @IsNotEmpty()
  @IsString()
  name: string;

  @IsEmail()
  email: string;

  @MinLength(6)
  password: string;

  @IsNotEmpty()
  @IsString()
  phone: string;
}
