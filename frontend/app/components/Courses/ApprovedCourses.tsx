"use client";
import React from "react";
import { useGetApprovedCoursesQuery } from "../../../redux/features/courses/coursesApi";
import Loader from "../Loader/Loader";

const ApprovedCourses = () => {
  const { data, error, isLoading } = useGetApprovedCoursesQuery({});

  if (isLoading) return <Loader />;
  if (error) return <p className="text-red-500">Error loading courses</p>;

  return (
    <div className="mt-28 flex-grow px-4 lg:px-16">
      <h1 className="text-3xl font-bold mb-6 text-center">All Courses</h1>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
        {data.courses.map((course: any) => (
          <div key={course._id} className="card w-full bg-base-100 shadow-xl">
            <figure>
              <img
                src={
                  course.image ? course.image.url : "/assets/default-course.jpg"
                }
                alt={course.name}
                className="w-full h-48 object-cover"
              />
            </figure>
            <div className="card-body">
              <h2 className="card-title">{course.name}</h2>
              <p>{course.description}</p>
              <div className="flex justify-between mt-4">
                <span className="text-lg font-bold">Seats: {course.seat}</span>
                <span className="text-lg font-bold">
                  Price: ${course.price}
                </span>
              </div>
              <div className="card-actions justify-end">
                <button className="btn btn-primary">Enroll Now</button>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default ApprovedCourses;
