import { useState, useEffect } from 'react';
import styled from 'styled-components';

import { format } from 'date-fns';
import { startOfMonth, endOfMonth, startOfWeek, endOfWeek } from 'date-fns';
import { isSameMonth, isSameDay, addDays } from 'date-fns';

import { CalendarMonth } from 'components';
import { RecordApis } from 'api';
import { PloggingDayState } from 'types';

import DownSvg from 'assets/icons/angle-down.svg?react';

interface CalendarProps {
  selectedDate: Date | null;
  setSelectedDate: (date: Date | null) => void;
}

interface DotProps {
  $exists: boolean;
}

interface PloggingState {
  [key: string]: boolean;
}

const Calendar = (props: CalendarProps) => {
  const [currentDate, setCurrentDate] = useState<Date>(new Date());
  const [calendar, setCalendar] = useState<JSX.Element[]>();
  const [ploggingStates, setPloggingStates] = useState<PloggingState>();

  const selectDate = (e: React.MouseEvent<HTMLElement, MouseEvent>) => {
    const target = e.target as HTMLElement;
    const dateValue = (target.firstChild as HTMLInputElement).value;
    const date = new Date(dateValue);
    props.setSelectedDate(date);
    if (ploggingStates) {
      initWeekCalendar(date);
    }
  };

  const initCalendar = () => {
    const rows = [];
    let days = [];
    let dots = [];
    const monthStart = startOfMonth(currentDate);
    const monthEnd = endOfMonth(monthStart);
    const startDate = startOfWeek(monthStart);
    const endDate = endOfWeek(monthEnd);
    let day = startDate;

    while (day <= endDate) {
      for (let i = 0; i < 7; i++) {
        days.push(
          <S.Date
            className={`${
              isSameMonth(currentDate, new Date()) &&
              isSameDay(currentDate, day)
                ? 'today'
                : ''
            }`}
            key={day.getTime()}
            onClick={e => selectDate(e)}
          >
            <input type="hidden" value={day.toISOString()} />
            {isSameMonth(currentDate, day) ? format(day, 'd') : ''}
          </S.Date>,
        );

        dots.push(
          <S.Dot
            key={day.getTime()}
            $exists={
              ploggingStates![format(day, 'yyyy-MM-dd')] &&
              isSameMonth(currentDate, day)
                ? true
                : false
            }
          ></S.Dot>,
        );

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

  const initWeekCalendar = (date: Date) => {
    const startDate = startOfWeek(date);
    const row = [];
    const days = [];
    const dots = [];
    let day = startDate;
    for (let i = 0; i < 7; i++) {
      days.push(
        <S.Date
          className={`${
            isSameMonth(currentDate, new Date()) && isSameDay(currentDate, day)
              ? 'today'
              : ''
          } ${isSameDay(date, day) ? 'selected' : ''}`}
          key={day.getTime()}
          onClick={e => selectDate(e)}
        >
          <input type="hidden" value={day.toISOString()} />
          {isSameMonth(currentDate, day) ? format(day, 'd') : ''}
        </S.Date>,
      );

      dots.push(
        <S.Dot
          key={day.getTime()}
          $exists={ploggingStates![format(day, 'yyyy-MM-dd')] ? true : false}
        ></S.Dot>,
      );

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

  const handleChangeMode = () => {
    if (ploggingStates) {
      initCalendar();
    }
    props.setSelectedDate(null);
  };

  useEffect(() => {
    const initPloggingStates = async () => {
      try {
        const response = await RecordApis.getPloggingLogByMonth(
          format(currentDate, 'yyyy-MM-dd'),
        );

        const states: PloggingState = {};
        [...response.data.results].forEach((element: PloggingDayState) => {
          states[element.date] = element.exists;
        });
        setPloggingStates(states);
      } catch (err) {
        //console.log(err);
      }
    };

    initPloggingStates();
  }, [currentDate]);

  useEffect(() => {
    if (ploggingStates && currentDate) {
      initCalendar();
    }
  }, [ploggingStates]);

  return (
    <S.Wrap>
      <CalendarMonth
        currentDate={currentDate}
        setCurrentDate={setCurrentDate}
        setSelectedDate={props.setSelectedDate}
      />
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
          <S.StretchAccess onClick={handleChangeMode}>
            <DownSvg />
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
    color: ${({ theme }) => theme.color.dark};

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
    color: ${({ theme }) => theme.color.dark};

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

    &.active:active {
      background-color: ${({ theme }) => theme.color.main};
      color: ${({ theme }) => theme.color.white};
    }
  `,
  Dots: styled.ul`
    height: 12px;
    display: grid;
    grid-template-columns: repeat(7, 1fr);
    justify-items: center;
    align-items: center;
  `,
  Dot: styled.li<DotProps>`
    display: flex;
    align-items: center;
    justify-content: center;
    width: 6px;
    height: 6px;
    border-radius: 3px;
    background-color: ${({ theme, $exists }) =>
      $exists ? theme.color.sub2 : 'transparent'};
  `,
  StretchAccess: styled.div`
    display: flex;
    width: 100%;
    justify-content: center;
    cursor: pointer;
  `,
};
