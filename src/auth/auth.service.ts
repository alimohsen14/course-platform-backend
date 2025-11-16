import {
  Injectable,
  BadRequestException,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { SignupDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}

  // =======================
  //        SIGNUP
  // =======================
  async signup(dto: SignupDto) {
    const exists = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (exists) {
      throw new BadRequestException('Email already exists');
    }

    const hashed = await bcrypt.hash(dto.password, 10);

    const user = await this.prisma.user.create({
      data: {
        name: dto.name,
        email: dto.email,
        password: hashed,
        phone: dto.phone,
      },
    });

    return {
      message: 'User created successfully',
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
      },
    };
  }

  // =======================
  //        LOGIN
  // =======================
  async login(dto: LoginDto) {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (!user) {
      throw new NotFoundException('Email or password is incorrect');
    }

    const match = await bcrypt.compare(dto.password, user.password);
    if (!match) {
      throw new BadRequestException('Email or password is incorrect');
    }

    return {
      message: 'Logged in successfully',
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
      },
    };
  }
}
