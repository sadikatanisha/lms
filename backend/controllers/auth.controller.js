const express = require("express");
const User = require("../models/User");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const CatchAsyncError = require("../middleware/catchAsyncErrors");
const ErrorHandler = require("../utils/ErrorHandler");

// REGISTER
const registerUser = CatchAsyncError(async (req, res, next) => {
  try {
    const { name, email, password } = req.body;
    const user = await User.create({
      name,
      email,
      password,
    });
    const savedUser = await user.save();
    res.status(200).json(savedUser);
  } catch (err) {
    res.status(500).json(err);
  }
});

// LOGIN
const loginUser = CatchAsyncError(async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return next(new ErrorHandler("Please enter email and password", 400));
    }
    const user = await User.findOne({ email }).select("+password");
    if (!user) {
      return next(new ErrorHandler("Invalid email or password", 400));
    }
    const isPasswordMatch = await user.comparePassword(password);
    if (!isPasswordMatch) {
      return next(new ErrorHandler("Invalid email or password", 400));
    }
    const token = jwt.sign(
      { _id: user._id, username: user.username, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "3d" }
    );

    res.cookie("token", token).status(200).json(user);
  } catch (err) {
    res.status(500).json(err);
  }
});

// LOGOUT
const logoutUser = CatchAsyncError(async (req, res, next) => {
  try {
    res
      .clearCookie("token", { SameSite: "none", secure: true })
      .status(200)
      .send("User logged out successfully!");
  } catch (err) {
    res.status(500).json(err);
  }
});

// REFETCH USER
const refetchUser = CatchAsyncError(async (req, res, next) => {
  const token = req.cookies.token;
  jwt.verify(token, process.env.JWT_SECRET, {}, async (err, data) => {
    if (err) {
      return res.status(404).json(err);
    }
    res.status(200).json(data);
  });
});

module.exports = { registerUser, loginUser, logoutUser, refetchUser };
