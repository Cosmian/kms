import { Button, Table, Tag } from 'antd'
import React, { useEffect, useState } from 'react'
import { getNoTTLVRequest } from './utils'

interface AccessRight {
    objectUid: string;
    objectState: string;
    owner: string;
    operations: string[];
}

const AccessObtainedList: React.FC = () => {
    const [isLoading, setIsLoading] = useState(false);
    const [accessRights, setAccessRights] = useState<AccessRight[]>([]);
    const [res, setRes] = useState<string | undefined>(undefined);


    // TODO Update fields name from server response - when auth is OK
    const columns = [
        {
            title: 'Object UID',
            dataIndex: 'objectUid',
            key: 'objectUid',
        },
        {
            title: 'State',
            dataIndex: 'objectState',
            key: 'objectState',
            render: (state: string) => (
                <Tag color={state === 'Active' ? 'green' : 'orange'}>{state}</Tag>
            ),
        },
        {
            title: 'Owner',
            dataIndex: 'owner',
            key: 'owner',
        },
        {
            title: 'Granted Operations',
            dataIndex: 'operations',
            key: 'operations',
            render: (operations: string[]) => (
                <span>
                    {operations.map(op => (
                        <Tag key={op} color="blue">{op}</Tag>
                    ))}
                </span>
            ),
        },
    ];

    const fetchAccessRights = async () => {
        setIsLoading(true);
        setRes(undefined);
        setAccessRights([])
        try {
            const response = await getNoTTLVRequest("/access/obtained");
            console.log(response)
            if (response.length) {
                setAccessRights(response);
            } else {
                setRes("Empty result");
            }

        } catch (e) {
            setRes(`Error listing objects: ${e}`)
            console.error("Error listing objects:", e);
        } finally {
            setIsLoading(false);
        }
    };

    useEffect(() => {
        fetchAccessRights();
    }, []);

    return (
        <div className="bg-white rounded-lg shadow-md p-6 m-4">
            <div className="flex justify-between items-center mb-6">
                <h1 className="text-2xl font-bold ">Access rights obtained</h1>
                <Button
                    type="primary"
                    onClick={fetchAccessRights}
                    loading={isLoading}
                    className="bg-primary hover:bg-blue-700 border-0"
                >
                    Refresh
                </Button>
            </div>

            <div className="mb-8 text-gray-600 space-y-2">
                <p>List of objects you have been granted access to, along with their current state, owner, and the operations you can perform.</p>
            </div >
            <Table
                dataSource={accessRights}
                columns={columns}
                rowKey="objectUid"
                loading={isLoading}
                pagination={{ pageSize: 10 }}
                className="border rounded"
            />
            {res && <div>{res}</div>}
        </div >
    );
};

export default AccessObtainedList;
