"use client";
import React from "react";
import DashboardSidebar from "../../components/Dashboard/DashboardSidebar";
import Heading from "../../utils/Heading";
import CreateCourse from "../../components/Dashboard/Course/CreateCourse";
import { InstructroProtected } from "../../../app/hooks/adminProtected";

type Props = {};

const page = (props: Props) => {
  return (
    <InstructroProtected>
      <div>
        <Heading
          title={"Creati - Dashboard"}
          description="dashboard"
          keywords="dashboard"
        />
        <div className="flex">
          <div className="1500:w-[16%] w-1/5">
            <DashboardSidebar />
          </div>
          <div className="w-[85%]">
            <CreateCourse />
          </div>
        </div>
      </div>
    </InstructroProtected>
  );
};

export default page;
