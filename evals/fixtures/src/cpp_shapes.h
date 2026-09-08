#ifndef CPP_SHAPES_H
#define CPP_SHAPES_H

#include <cmath>
#include <string>
#include <vector>

class Shape {
 public:
  virtual double area() const = 0;
  virtual const char *kind() const;
  virtual ~Shape();
};

class Rectangle : public Shape {
 public:
  Rectangle(double w, double h) : w_(w), h_(h) {}
  double area() const override { return w_ * h_; }
  const char *kind() const override { return "rectangle"; }
  double perimeter() const { return 2.0 * (w_ + h_); }

 private:
  double w_;
  double h_;
};

class Circle : public Shape {
 public:
  explicit Circle(double r) : r_(r) {}
  double area() const override { return M_PI * r_ * r_; }
  const char *kind() const override { return "circle"; }

 private:
  double r_;
};

double total_area(const std::vector<Shape *> &shapes);
std::string describe(const std::string &prefix, const std::vector<int> &nums);
const char *shape_kind(const Shape *s);
Rectangle *make_rect(double w, double h);
Circle *make_circle(double r);
double rect_perimeter(const Rectangle *r);

#endif  // CPP_SHAPES_H
