/* eslint-disable */
import {
  Injectable,
  BadRequestException,
  NotFoundException,
  ForbiddenException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import axios from 'axios';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

interface GoogleTokenResponse {
  access_token: string;
}
interface GoogleUserInfo {
  id: string;
  email: string;
  name: string;
}

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}

  // --------------------------
  // TOKEN CREATION
  // --------------------------
  generateTokens(userId: string, email: string) {
    const accessToken = this.jwt.sign(
      { sub: userId, email },
      { expiresIn: '15m' },
    );
    const refreshToken = this.jwt.sign(
      { sub: userId, email },
      { expiresIn: '7d' },
    );
    return { accessToken, refreshToken };
  }

  async updateRefreshToken(id: string, refresh: string) {
    await this.prisma.user.update({
      where: { id },
      data: { refreshToken: refresh },
    });
  }

  // --------------------------
  // SIGNUP
  // --------------------------
  async signup(dto: any) {
    const exists = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });
    if (exists) throw new BadRequestException('Email already exists');

    const hashed = await bcrypt.hash(dto.password, 10);

    const user = await this.prisma.user.create({
      data: {
        email: dto.email,
        name: dto.name,
        phone: dto.phone,
        password: hashed,
        provider: 'LOCAL',
      },
    });

    const tokens = this.generateTokens(user.id, user.email);
    await this.updateRefreshToken(user.id, tokens.refreshToken);

    return { message: 'User created', ...tokens, user };
  }

  // --------------------------
  // LOGIN
  // --------------------------
  async login(dto: any) {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (!user) throw new NotFoundException('Email or password incorrect');
    if (!user.password && user.provider === 'GOOGLE')
      throw new BadRequestException('Login with Google');

    const match = await bcrypt.compare(dto.password, user.password || '');
    if (!match) throw new BadRequestException('Email or password incorrect');

    const tokens = this.generateTokens(user.id, user.email);
    await this.updateRefreshToken(user.id, tokens.refreshToken);

    return { message: 'Logged in', ...tokens, user };
  }

  // --------------------------
  // GET PROFILE
  // --------------------------
  async getProfile(id: string) {
    return this.prisma.user.findUnique({ where: { id } });
  }
  // --------------------------
  // UPDATE PROFILE
  // --------------------------
  async updateProfile(userId: string, data: { name?: string; phone?: string }) {
    const updatedUser = await this.prisma.user.update({
      where: { id: userId },
      data,
    });

    return {
      message: 'Profile updated successfully',
      user: updatedUser,
    };
  }
  // --------------------------
  // CHANGE PASSWORD
  // --------------------------
  async changePassword(
    userId: string,
    dto: { currentPassword: string; newPassword: string },
  ) {
    const { currentPassword, newPassword } = dto;

    const user = await this.prisma.user.findUnique({ where: { id: userId } });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    if (!user.password || user.provider === 'GOOGLE') {
      throw new BadRequestException(
        'Password change is only available for email/password accounts',
      );
    }

    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      throw new BadRequestException('Current password is incorrect');
    }

    if (!newPassword || newPassword.length < 6) {
      throw new BadRequestException(
        'New password must be at least 6 characters long',
      );
    }

    const hashed = await bcrypt.hash(newPassword, 10);

    await this.prisma.user.update({
      where: { id: userId },
      data: { password: hashed },
    });

    return {
      message: 'Password updated successfully',
    };
  }

  // --------------------------
  // GOOGLE LOGIN
  // --------------------------
  async googleLogin(code: string) {
    const client_id = this.config.get('GOOGLE_CLIENT_ID');
    const client_secret = this.config.get('GOOGLE_CLIENT_SECRET');
    const redirect_uri = this.config.get('GOOGLE_REDIRECT_URI');

    const tokenRes = await axios.post<GoogleTokenResponse>(
      'https://oauth2.googleapis.com/token',
      new URLSearchParams({
        client_id,
        client_secret,
        redirect_uri,
        grant_type: 'authorization_code',
        code,
      }),
    );

    const { access_token } = tokenRes.data;
    if (!access_token) throw new BadRequestException('Google login failed');

    const userInfo = await axios.get<GoogleUserInfo>(
      'https://www.googleapis.com/oauth2/v2/userinfo',
      { headers: { Authorization: `Bearer ${access_token}` } },
    );

    const { email, name, id: providerId } = userInfo.data;

    const exists = await this.prisma.user.findUnique({ where: { email } });

    if (!exists) {
      return {
        isNewUser: true,
        user: { email, name, providerId },
        tokens: null,
      };
    }

    const tokens = this.generateTokens(exists.id, exists.email);
    await this.updateRefreshToken(exists.id, tokens.refreshToken);

    return { isNewUser: false, user: exists, tokens };
  }

  // --------------------------
  // COMPLETE GOOGLE SIGNUP
  // --------------------------
  async googleCompleteSignup(dto: any) {
    const { email, name, phone, providerId } = dto;

    const exists = await this.prisma.user.findUnique({ where: { email } });
    if (exists) throw new BadRequestException('User already exists');

    const user = await this.prisma.user.create({
      data: {
        email,
        name,
        phone,
        password: null,
        provider: 'GOOGLE',
        providerId,
      },
    });

    const tokens = this.generateTokens(user.id, user.email);
    await this.updateRefreshToken(user.id, tokens.refreshToken);

    return { message: 'Google signup done', ...tokens, user };
  }

  // --------------------------
  // REFRESH TOKEN
  // --------------------------
  async refresh(refreshToken: string) {
    try {
      const payload = this.jwt.verify(refreshToken);
      const user = await this.prisma.user.findUnique({
        where: { id: payload.sub },
      });

      if (!user || user.refreshToken !== refreshToken)
        throw new ForbiddenException('Invalid refresh');

      const tokens = this.generateTokens(user.id, user.email);
      await this.updateRefreshToken(user.id, tokens.refreshToken);

      return tokens;
    } catch {
      throw new ForbiddenException('Invalid refresh');
    }
  }
}
