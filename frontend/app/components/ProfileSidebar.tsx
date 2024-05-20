import React, { FC } from "react";
import Image from "next/image";
import avatarDefault from "../../public/assets/default-avatar.png";
import { RiLockPasswordLine } from "react-icons/ri";
import { SiCoursera } from "react-icons/si";
import { AiOutlineLogout } from "react-icons/ai";
import Link from "next/link";
type Props = {
  user: any;
  active: number;
  avatar: string | null;
  setActive: (active: number) => void;
  logOutHandler: any;
};

const ProfileSidebar: FC<Props> = ({
  user,
  active,
  avatar,
  setActive,
  logOutHandler,
}) => {
  return (
    <div className="w-full">
      <div
        className={`w-full flex items-center px-3 py-4 ursor-pointer ${
          active === 1 ? "dark:bg-slate-800 bg-white" : "bg-trasparent"
        }`}
        onClick={() => setActive(1)}
      >
        <Image
          width={20}
          height={20}
          src={
            user.avatar || avatar ? user.avatar.url || avatar : avatarDefault
          }
          alt=""
          className="w-[20px] h-[20px]  rounded-full cursor-pointer"
        />
        <h5 className="pl-2 800px:block hidden font-Poppins dark:text-white text-black">
          My Account
        </h5>
      </div>
      <div
        className={`w-full flex items-center px-3 py-4 cursor-pointer ${
          active === 2 ? "dark:bg-slate-800 bg-white" : "bg-transparent"
        }`}
        onClick={() => setActive(2)}
      >
        <RiLockPasswordLine size={20} className="dark:text-white test-black" />
        <h5 className="pl-2 800px:block hidden font-Poppins dark:text-white text-black">
          Change Password
        </h5>
      </div>
      <div
        className={`w-full flex items-center px-3 py-4 cursor-pointer ${
          active === 3 ? "dark:bg-slate-800 bg-white" : "bg-transparent"
        }`}
        onClick={() => setActive(3)}
      >
        <SiCoursera size={20} className="dark:text-white test-black" />
        <h5 className="pl-2 800px:block hidden font-Poppins dark:text-white text-black">
          Enrolled Courses
        </h5>
      </div>
      {/* FOR ADMIN */}
      {user.role === "admin" && (
        <Link href="/dashboard">
          <div
            className={`w-full flex items-center px-3 py-4 cursor-pointer ${
              active === 6 ? "dark:bg-slate-800 bg-white" : "bg-transparent"
            }`}
            onClick={() => setActive(6)}
          >
            <SiCoursera size={20} className="dark:text-white test-black" />
            <h5 className="pl-2 800px:block hidden font-Poppins dark:text-white text-black">
              Dashboard
            </h5>
          </div>
        </Link>
      )}

      {/* LOGOUT */}
      <div
        className={`w-full flex items-center px-3 py-4 cursor-pointer ${
          active === 4 ? "dark:bg-slate-800 bg-white" : "bg-transparent"
        }`}
        onClick={() => logOutHandler()}
      >
        <AiOutlineLogout size={20} className="dark:text-white test-black" />
        <h5 className="pl-2 800px:block hidden font-Poppins dark:text-white text-black">
          Logout
        </h5>
      </div>
    </div>
  );
};

export default ProfileSidebar;
