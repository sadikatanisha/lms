"use client";
import React, { useEffect, useState } from "react";
import { useCreateCourseMutation } from "../../../../redux/features/courses/coursesApi";
import toast from "react-hot-toast";

import Image from "next/image";
import { styles } from "../../../../app/styles/style";

type Props = {};

const CreateCourse = (props: Props) => {
  const [createCourse, { isLoading, isSuccess, error }] =
    useCreateCourseMutation();

  useEffect(() => {
    if (isSuccess) {
      toast.success("Course Created Successfully");
    }
    if (error) {
      if ("data" in error) {
        const errorMessage = error as any;
        toast.error(errorMessage.data.message);
      }
    }
  }, [isLoading, isSuccess, error]);

  const [courseInfo, setCourseInfo] = useState({
    name: "",
    description: "",
    image: "",
    price: "",
    seat: "",
  });

  const handleSubmit = async (e: any) => {
    e.preventDefault();
    const data = courseInfo;
    if (!isLoading) {
      await createCourse(data);
    }
  };

  const handleFileChange = (e: any) => {
    const file = e.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (e: any) => {
        if (reader.result !== null && typeof reader.result === "string") {
          setCourseInfo({ ...courseInfo, image: reader.result });
        }
      };
      reader.readAsDataURL(file);
    }
  };

  return (
    <div className="w-full flex min-h-screen">
      <div className="w-[80%] m-auto mt-24">
        <form onSubmit={handleSubmit} className={`${styles.label}`}>
          <label htmlFor="name">Course Name</label>
          <div>
            <input
              type="text"
              required
              value={courseInfo.name}
              onChange={(e: any) =>
                setCourseInfo({ ...courseInfo, name: e.target.value })
              }
              id="name"
              placeholder="Course Name"
              className={`${styles.input}`}
            />
          </div>
          <br />
          <div className="mb-5">
            <label htmlFor="description" className={`${styles.label}`}>
              Course Description
            </label>
            <textarea
              id="description"
              cols={30}
              rows={8}
              placeholder="Write a description..."
              className={`${styles.input} !h-min py-2`}
              value={courseInfo.description}
              onChange={(e: any) =>
                setCourseInfo({ ...courseInfo, description: e.target.value })
              }
            ></textarea>
          </div>
          <br />
          <div className="w-full flex justify-between">
            <div className="w-[50%]">
              <label htmlFor="price" className={`${styles.label}`}>
                Price
              </label>
              <input
                type="number"
                required
                value={courseInfo.price}
                onChange={(e: any) =>
                  setCourseInfo({ ...courseInfo, price: e.target.value })
                }
                id="price"
                placeholder="Price"
                className={`${styles.input}`}
              />
            </div>
            <div className="w-[45%]">
              <label htmlFor="seat" className={`${styles.label}`}>
                Seat
              </label>
              <input
                type="number"
                required
                value={courseInfo.seat}
                onChange={(e: any) =>
                  setCourseInfo({ ...courseInfo, seat: e.target.value })
                }
                id="seat"
                placeholder="Seat"
                className={`${styles.input}`}
              />
            </div>
          </div>
          <br />
          <div className="w-full">
            <input
              type="file"
              accept="image/*"
              id="file"
              className="mt-5"
              onChange={handleFileChange}
            />
          </div>
          {courseInfo.image && (
            <div className="mt-5">
              <Image
                src={courseInfo.image}
                alt="Course Image"
                width={200}
                height={200}
                priority
              />
            </div>
          )}
          <br />
          <div className="w-full flex items-center justify-end">
            <input
              type="submit"
              value="Create Course"
              className="w-full 800px:w-[180px] h-[40px] bg-[#37a39a] text-center text-[#fff] rounded mt-8 cursor-pointer"
            />
          </div>
          <br />
          <br />
        </form>
      </div>
      <div className="w-[20%] h-screen mt-[100px] fixed z-[-1] top-18 right-0"></div>
    </div>
  );
};

export default CreateCourse;
