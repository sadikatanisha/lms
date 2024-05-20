"use client";
import React, { FC, useEffect, useState } from "react";
import { SiCoursera } from "react-icons/si";
import { IoArrowForward, IoHomeOutline } from "react-icons/io5";
import { BiArrowBack } from "react-icons/bi";
import { IconButton, Typography } from "@mui/material";
import Link from "next/link";
import Image from "next/image";
import { useSelector } from "react-redux";
import { useTheme } from "next-themes";
import avatarDefault from "../../../public/assets/default-avatar.png";
import { AiOutlineLogout } from "react-icons/ai";
interface itemProps {
  title: string;
  to: string;
  icon: JSX.Element;
  selected: string;
  setSelected: any;
}

const Item: FC<itemProps> = ({ title, to, icon, selected, setSelected }) => {
  return (
    <li
      className={`my-2 p-2 rounded-lg flex items-center ${
        selected === title
          ? "bg-blue-500 text-white"
          : "text-gray-700 dark:text-white hover:bg-gray-200 dark:hover:bg-gray-600"
      }`}
      onClick={() => setSelected(title)}
    >
      {icon}
      <Link href={to} className="ml-3">
        {title}
      </Link>
    </li>
  );
};

const Sidebar = () => {
  const { user } = useSelector((state: any) => state.auth);
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [selected, setSelected] = useState("Dashboard");
  const { theme, setTheme } = useTheme();

  // Define sidebar items for each role
  const userItems = [
    {
      title: "Selected Classes",
      to: "/selected-classes",
      icon: <IoHomeOutline />,
    },
    {
      title: "Enrolled Classes",
      to: "/enrolled-classes",
      icon: <IoHomeOutline />,
    },
    {
      title: "Transaction History",
      to: "/transaction-history",
      icon: <IoHomeOutline />,
    },
  ];

  const instructorItems = [
    {
      title: "Create Course",
      to: "/dashboard/create-course",
      icon: <IoHomeOutline />,
    },
    {
      title: "My Classes",
      to: "/dashboard/courses",
      icon: <IoHomeOutline />,
    },
  ];

  const adminItems = [
    {
      title: "Manage Courses",
      to: "/dashboard/manage-courses",
      icon: <IoHomeOutline />,
    },
    { title: "Users", to: "/dashboard/users", icon: <SiCoursera /> },
  ];
  const commonItems = [
    {
      title: "Home",
      to: "/",
      icon: <IoHomeOutline />,
    },
    {
      title: "All Classes",
      to: "/all-classes",
      icon: <SiCoursera />,
    },
    {
      title: "Logout",
      to: "/logout",
      icon: <AiOutlineLogout />,
    },
  ];
  // Determine which items to show based on user role
  let sidebarItems;
  if (user?.role === "admin") {
    sidebarItems = adminItems;
  } else if (user?.role === "instructor") {
    sidebarItems = instructorItems;
  } else {
    sidebarItems = userItems;
  }

  return (
    <div
      className={`fixed top-0 left-0 h-full ${
        isCollapsed ? "w-16" : "w-64"
      } bg-white dark:bg-gray-900 transition-width duration-300`}
    >
      <div className="flex items-center justify-between p-4">
        <Link href="/">
          <h3 className="text-2xl font-bold dark:text-white">CREATi</h3>
        </Link>
        <IconButton
          onClick={() => setIsCollapsed(!isCollapsed)}
          className="text-black dark:text-white"
        >
          {isCollapsed ? <IoArrowForward /> : <BiArrowBack />}
        </IconButton>
      </div>
      {!isCollapsed && (
        <div className="p-4">
          <div className="flex justify-center items-center mb-4">
            <Image
              alt="profile-user"
              width={100}
              height={100}
              src={user.avatar ? user.avatar.url : avatarDefault}
              className="rounded-full border-4 border-blue-500"
            />
          </div>
          <div className="text-center mb-4">
            <Typography
              variant="h4"
              className="text-lg font-medium text-black dark:text-white"
            >
              {user?.name}
            </Typography>
            <Typography
              variant="h4"
              className="text-lg font-medium text-black dark:text-white"
            >
              {user?.role}
            </Typography>
          </div>
        </div>
      )}
      <ul className={`px-4 space-y-2 ${isCollapsed ? "hidden" : "block"}`}>
        {sidebarItems.map((item) => (
          <Item
            key={item.title}
            title={item.title}
            to={item.to}
            icon={item.icon}
            selected={selected}
            setSelected={setSelected}
          />
        ))}
        <hr className="my-4 border-t border-gray-200 dark:border-gray-600" />
        {commonItems.map((item) => (
          <Item
            key={item.title}
            title={item.title}
            to={item.to}
            icon={item.icon}
            selected={selected}
            setSelected={setSelected}
          />
        ))}
      </ul>
    </div>
  );
};

export default Sidebar;
