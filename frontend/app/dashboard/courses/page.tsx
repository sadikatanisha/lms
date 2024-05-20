"use client";

import React from "react";
import Heading from "../../utils/Heading";
import DashboardSidebar from "../../components/Dashboard/DashboardSidebar";
import { InstructroProtected } from "../../../app/hooks/adminProtected";
import AllCourses from "../../components/Dashboard/Course/AllUserCourses";

type Props = {};

const Page = (props: Props) => {
  return (
    <div>
      <InstructroProtected>
        <Heading
          title={"Creati - Dashboard"}
          description="dashboard"
          keywords="dashboard"
        />
        <div className="flex h-screen">
          <div className="w-1/4 h-full">
            <DashboardSidebar />
          </div>
          <div className="w-3/4 h-full p-6">
            <AllCourses />
          </div>
        </div>
      </InstructroProtected>
    </div>
  );
};

export default Page;
