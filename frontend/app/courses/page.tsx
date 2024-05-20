"use client";
import React, { useState } from "react";
import ApprovedCourses from "../components/Courses/ApprovedCourses";
import Heading from "../utils/Heading";
import Header from "../components/Header";
type Props = {};

const page = (props: Props) => {
  const [open, setOpen] = useState(false);
  const [activeItem, setActiveItem] = useState(0);
  const [route, setRoute] = useState("Login");
  return (
    <div>
      <Heading
        title="Creati"
        description="A creative learning platform"
        keywords="art,creativity,learn"
      />
      <Header
        open={open}
        activeItem={activeItem}
        setOpen={setOpen}
        route={route}
        setRoute={setRoute}
      />
      <ApprovedCourses />
    </div>
  );
};

export default page;
