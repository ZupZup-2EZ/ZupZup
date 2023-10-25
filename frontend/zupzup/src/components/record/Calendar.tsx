import { useState, useEffect } from 'react';
import styled from 'styled-components';

import { format } from 'date-fns';
import { startOfMonth, endOfMonth, startOfWeek, endOfWeek } from 'date-fns';
import { isSameMonth, isSameDay, addDays } from 'date-fns';

import { CalendarMonth } from 'components';

import DoubleDashSvg from 'assets/icons/double_dash.svg?react';

interface CalendarProps {
  selectedDate: Date | null;
  setSelectedDate: (date: Date) => void;
}

const Calendar = (props: CalendarProps) => {
  const now = new Date();
  const [calendar, setCalendar] = useState<JSX.Element[]>();

  const monthStart = startOfMonth(now);
  const monthEnd = endOfMonth(monthStart);
  const startDate = startOfWeek(monthStart);
  const endDate = endOfWeek(monthEnd);

  const selectDate = (e: React.MouseEvent<HTMLElement, MouseEvent>) => {
    const target = e.target as HTMLElement;
    const dateValue = (target.firstChild as HTMLInputElement).value;
    const date = new Date(dateValue);
    props.setSelectedDate(date);
    initWeekCalendar(date);
  };

  const initWeekCalendar = (date: Date) => {
    const startDate = startOfWeek(date);
    const row = [];
    const days = [];
    const dots = [];
    let day = startDate;
    for (let i = 0; i < 7; i++) {
      days.push(
        <S.Date
          className={`${isSameMonth(now, day) ? 'active' : ''} ${
            isSameDay(now, day) ? 'today' : ''
          } ${isSameDay(date, day) ? 'selected' : ''}`}
          key={day.getTime()}
          onClick={e => selectDate(e)}
        >
          <input type="hidden" value={day.toISOString()} />
          {isSameMonth(now, day) ? format(day, 'd') : ''}
        </S.Date>,
      );

      if (isSameMonth(now, day)) {
        dots.push(<S.Dot key={day.getTime()}></S.Dot>);
      }

      day = addDays(day, 1);
    }
    row.push(
      <S.Row key={day.getTime()}>
        <S.Week>{days}</S.Week>
        <S.Dots>{dots}</S.Dots>
      </S.Row>,
    );
    setCalendar([...row]);
  };

  const initCalendar = () => {
    const rows = [];
    let days = [];
    let dots = [];
    let day = startDate;

    while (day <= endDate) {
      for (let i = 0; i < 7; i++) {
        days.push(
          <S.Date
            className={`${isSameMonth(now, day) ? 'active' : ''} ${
              isSameDay(now, day) ? 'today' : ''
            }`}
            key={day.getTime()}
            onClick={e => selectDate(e)}
          >
            <input type="hidden" value={day.toISOString()} />
            {isSameMonth(now, day) ? format(day, 'd') : ''}
          </S.Date>,
        );

        if (isSameMonth(now, day)) {
          dots.push(<S.Dot key={day.getTime()}></S.Dot>);
        }

        day = addDays(day, 1);
      }
      rows.push(
        <S.Row key={day.getTime()}>
          <S.Week>{days}</S.Week>
          <S.Dots>{dots}</S.Dots>
        </S.Row>,
      );
      days = [];
      dots = [];
    }
    setCalendar([...rows]);
  };

  useEffect(() => {
    initCalendar();
  }, []);

  return (
    <S.Wrap>
      <CalendarMonth />
      <S.Calendar className={props.selectedDate === null ? 'month' : 'week'}>
        <S.DaysOfWeek>
          <S.NameOfDays>일</S.NameOfDays>
          <S.NameOfDays>월</S.NameOfDays>
          <S.NameOfDays>화</S.NameOfDays>
          <S.NameOfDays>수</S.NameOfDays>
          <S.NameOfDays>목</S.NameOfDays>
          <S.NameOfDays>금</S.NameOfDays>
          <S.NameOfDays>토</S.NameOfDays>
        </S.DaysOfWeek>
        {calendar}
        {props.selectedDate && (
          <S.StretchAccess>
            <DoubleDashSvg />
          </S.StretchAccess>
        )}
      </S.Calendar>
    </S.Wrap>
  );
};

export default Calendar;

const S = {
  Wrap: styled.div`
    width: 100%;
    background-color: ${({ theme }) => theme.color.background};
  `,
  Calendar: styled.div`
    &.month {
      min-height: 364px;
    }

    background-color: ${({ theme }) => theme.color.white};
    border-radius: 0 0 8px 8px;
    box-shadow: 0px 4px 4px 0px rgba(0, 0, 0, 0.04);
    padding: 10px 0;
  `,
  DaysOfWeek: styled.ul`
    display: grid;
    grid-template-columns: repeat(7, 1fr);
    justify-items: center;
    margin: 0 0 20px 0;
  `,
  NameOfDays: styled.li`
    &:first-child {
      color: ${({ theme }) => theme.color.warning};
    }

    &:last-child {
      color: ${({ theme }) => theme.color.sub2};
    }
  `,
  Row: styled.div`
    margin: 0 0 20px 0;
  `,
  Week: styled.ul`
    display: grid;
    grid-template-columns: repeat(7, 1fr);
    justify-items: center;
  `,
  Date: styled.li`
    display: flex;
    align-items: center;
    justify-content: center;
    width: 30px;
    height: 30px;
    border-radius: 15px;
    font-size: ${({ theme }) => theme.font.size.focus3};
    font-family: ${({ theme }) => theme.font.family.focus3};
    line-height: ${({ theme }) => theme.font.lineheight.focus3};

    &:first-child {
      color: ${({ theme }) => theme.color.warning};
    }

    &:last-child {
      color: ${({ theme }) => theme.color.sub2};
    }

    &.today {
      border: 2px dashed ${({ theme }) => theme.color.main};
    }

    &.selected {
      background-color: ${({ theme }) => theme.color.main};
      color: ${({ theme }) => theme.color.white};
    }

    &.active:hover {
      background-color: ${({ theme }) => theme.color.main};
      color: ${({ theme }) => theme.color.white};
      cursor: pointer;
    }
  `,
  Dots: styled.ul`
    height: 12px;
    display: grid;
    grid-template-columns: repeat(7, 1fr);
    justify-items: center;
    align-items: center;
  `,
  Dot: styled.li`
    display: flex;
    align-items: center;
    justify-content: center;
    width: 6px;
    height: 6px;
    border-radius: 3px;
    background-color: ${({ theme }) => theme.color.sub2};
  `,
  StretchAccess: styled.div`
    display: flex;
    width: 100%;
    justify-content: center;
  `,
};
