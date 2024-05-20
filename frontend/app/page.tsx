"use client";
import React, { FC, useState } from "react";
import Heading from "./utils/Heading";
import Header from "./components/Header";
import HeroSlider from "./components/HeroSlider";
import Footer from "./components/Footer";
import ApprovedCourses from "./components/Courses/ApprovedCourses";

interface Props {}

const Page: FC<Props> = (props) => {
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
      <HeroSlider />
      <ApprovedCourses />
      <Footer />
    </div>
  );
};

export default Page;
